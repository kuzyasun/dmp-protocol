# P25 host and simulation readiness report — 2026-10-16

## Status and conclusion

**Owner disposition, 2026-10-13:** the
[continuation decision record](DMP_Continuation_Decisions_2026-10-13.md) accepts
the remaining multi-peer, retry-profile, handshake-transport and SAMPLE-1
epoch-owner software scope. It selects S3/C3 for final physical qualification
and explicitly defers non-Espressif physical qualification to a future stage.
Older references below to non-Espressif runtime as a current acceptance blocker
are superseded for first-version S3/C3 acceptance. Other outstanding evidence
remains required; no test result or package status changes with this decision.

This report consolidates accepted host/simulation evidence and the bounded
physical smoke results available for P25. It is not a release approval. P25
remains pending because P12, the P01 acceptance umbrella, and P01C target
qualification are still open. Host memory estimates and provider-only MCU
measurements do not guarantee whole-device operation. The existing physical
smoke evidence below is limited to unauthenticated ESP-NOW/Core echo and
coredump extraction; it does not qualify the DMP endpoint or P01C.

The P21 peer work is accepted for functional host evidence under the owner's
explicit disposition, with an unresolved historical provenance caveat. No
clean-room or complete-independence claim is made.

## Current software gates and bounded physical smoke — 2026-10-15

The agreed P12/P13/P15 host behavior and the finite P01 provider/secret-copy
inventory are implemented and exercised. The current RBO host gate
(`job_01M4Y9RXZZMT59095HMED352QN`) completed these checks successfully:

- `ctest --test-dir build/rbo-final-noise --output-on-failure --parallel 1`:
  2/2 upstream Noise tests passed.
- `ctest --test-dir build/rbo-final --output-on-failure --parallel 1 -E
  '^(memory\.mcu_abi|memory\..*\.layout)$'`: 143/143 DMP CTests passed. The
  owner deferred the ARM ABI probe and its seven dependent layout checks.
- `python3 -m unittest discover -s tests/peer/tests -v`: 439 tests ran, 438
  passed, 1 skipped.
- The Node crypto-vector check reported 4 fixtures, 64 packets, 44 mutations,
  64 wrong-key rejections, 164 structural rejections, and 8 fixture-policy
  rejections.

The RBO job itself exited 1 after these gates because its trailing auxiliary
audit script contained an invalid regular expression. A separate RBO crosswalk
scan checked all 137 normative rows, primary/peer Test IDs, and 601 check
references; it found no missing files or symbols. That scan's final whitespace
check encountered CRLF handling in a Windows-originated note; local
`git diff --check --ignore-submodules=all` passes. The ledger remains at 36
whole-row passed / 101 partial. Its primary axis is 103 passed / 19 partial /
15 unrecorded; peer is 98 passed / 39 partial; P23 interop is 46 passed / 7
partial / 84 not-applicable. The 34 P12 rows remain 10 whole-row passed / 24
partial; five primary-partial rows retain target-only storage/reset/UART
evidence. No status was promoted just because a test reference exists.

The integrated one-endpoint scenario covers four authenticated peers, per-peer
routing/isolation, four pending reservations, two concurrent crypto scratch
leases, four active plus four draining associations, and a protected 4096-byte
service-2 request as 32 × 128-byte fragments. Both `four_serial` and
`four_parallel` pass. The profile's MTU remains explicit: 256-byte decoded Core
forward MTU and 263-byte encoded Stream R MTU.

The separately hashed two-attempt SAMPLE-1 READ manifest, real SEC-1 wrong
authenticated-sender rejection, handshake-to-transport COPY/BORROW/BUSY and
delayed/uncertain/cancel/expiry/stale-callback behavior, and fail-closed
application `sample_epoch` owner all have primary host regressions. Peer
evidence remains partial where the independent model does not implement a real
SEC-1 association or the full primary lifecycle; those limits are recorded in
the normative ledger rather than described as protocol passes. The GPT-6.1-sol
High reviewer found an epoch-index reuse risk when the association-fence
callback failed. The fix now preserves the index and latches storage failure
until a successful fence and reservation; reviewer follow-up found no further
actionable issue.

ESP-IDF 6.1 target compile/link job
`job_01M4Y7AX57YA2BFGEVCMT8EQPD` passed both probes:

```text
eim run "idf.py -C tests/embedded/esp32s3 -B build/rbo-final-esp32s3 -DIDF_TARGET=esp32s3 build" v6.1
eim run "idf.py -C tests/embedded/esp32c3 -B build/rbo-final-esp32c3 -DIDF_TARGET=esp32c3 build" v6.1
```

These are compile/link results only. Logs include Apple linker duplicate-library
warnings and ESP-IDF component include-validation warnings; both target
commands exited successfully.

### Local host recheck and ESP-NOW image compile — 2026-10-15

The local GCC 15.2.0 host build compiled 99/99 steps:

```text
cmake --build build/host-gcc --parallel 16
ctest --test-dir build/host-gcc --output-on-failure -E '^(memory\.mcu_abi|memory\..*\.layout)$'
```

CTest passed 144/144, including the profile suite's normative crosswalk
regression and `host.espnow_pair.serial_stub`. The filter excludes the
owner-deferred ARM ABI probe and seven dependent `memory.*.layout` checks.
Compilation emitted one warning in vendored Noise-C (`patterns.c`, `memchr` bounds); no build step failed.

With `DMP_P23_ENDPOINT_SEC_EXE` set to
`build/host-gcc/tests/security/dmp_test_endpoint_sec.exe` and
`PYTHONPATH=tests/peer`, the full Python peer suite ran 439 tests: 438 passed
and one exact-manifest cross-endpoint tombstone-pressure state was skipped
because it is unreachable under RADIO-1 and the independent peer has no
authorized service-1 DATA path to create it. The complete run included the
loopback TCP binding test. The targeted ledger regression passed 1/1; it checks
the primary and peer Test IDs for all 137 rows plus every recorded primary,
peer, and interop check path and declaration. Row statuses remain unchanged:
36 whole-row passed and 101 partial.

`node dev/dmp_verify_security_vectors.cjs` passed with 4 fixtures, 64 packets,
44 mutations, 64 wrong-key rejections, 164 structural rejections, and 8
fixture-policy rejections.

After the host gate, the CI-safe serial stub suite was extended to cover a C3
echo send callback marked failed even when the S3 trace contains a returned
echo. The runner remains fail-closed for this uncertain MAC outcome. The
focused Python suite passed 28/28 and
`ctest --test-dir build/host-gcc --output-on-failure -R
'^host\.espnow_pair\.serial_stub$'` passed 1/1.

RBO job `job_01M500ZBSPNC6ACZF2KCFT8D7D` passed ESP-IDF 6.1 compile/link for
the DMP pre-hardware probes on ESP32-S3 and ESP32-C3. A separate RBO job,
`job_01M50185NATG1KC9KB6M0NG7KK`, passed compile/link for the isolated
`tests/embedded/espnow_pair` smoke images on both targets, including the
1 MiB coredump partition. The commands were:

```text
eim run "idf.py -C tests/embedded/espnow_pair -B build/prehardware-20261015-espnow-s3 -DIDF_TARGET=esp32s3 build" v6.1
eim run "idf.py -C tests/embedded/espnow_pair -B build/prehardware-20261015-espnow-c3 -DIDF_TARGET=esp32c3 build" v6.1
```

Those images only exercise Core codec bytes over unauthenticated ESP-NOW echo;
they are not SEC-1 endpoint or DMP production-binding evidence. The RBO images
from the compile job above were not flashed. A previous authorized run on
2026-10-15 erased all four 4 MiB bench boards and flashed the earlier target
images. Its raw logs and artifacts remain under the ignored local directory
`dev/evidence/espnow-pair/`; a concise tracked summary is:

| Scenario | Result | Evidence boundary |
|---|---|---|
| S3 COM37 ↔ C3 COM36, 10 × 64-byte payload | PASS, 10/10 echoes | Unauthenticated Core echo; max decoded Core frame 68 bytes |
| S3 COM37 ↔ C3 COM36, 100 × 240-byte payload | PASS, 100/100 echoes | Max decoded Core frame 244 bytes, within the ESP-NOW v1 250-byte payload ceiling |
| S3 COM37 ↔ C3 COM38, 10 × 64-byte payload | PASS, 10/10 echoes | Unauthenticated Core echo |
| S3 COM37 ↔ C3 COM39, 10 × 64-byte payload | FAIL | First MAC completion failed; C3 received the probe but its echo completion failed |
| S3 COM37 with C3 COM36/38/39 in one radio context | FAIL after two echoes | COM39 send callback failed; this is three unauthenticated radio peers, not four authenticated DMP peers |
| Intentional coredump on COM37, COM36, COM38, COM39 | PASS on all four | 1 MiB partition read without flash writes; each extracted ELF decoded against its matching ESP-IDF 6.1 image |

### Physical callback diagnostic recheck — 2026-10-15

Fresh firmware `INFO` records reconfirmed the current port map: S3 on COM37,
and C3 on COM36, COM38, and COM39. The operator-authorized recheck did not
flash or erase devices:

| Scenario | Result | Evidence |
|---|---|---|
| S3 COM37 ↔ C3 COM36, 10 × 64-byte payload | FAIL | S3 recorded 10 returned echoes, but C3 reported one failed echo send callback; the strict counter gate failed. `dev/evidence/espnow-pair/pair-20261015T152131-458391400Z/` |
| S3 COM37 ↔ C3 COM39, 1 × 64-byte payload | FAIL | C3 received the probe, then both MAC send callbacks reported failure. `dev/evidence/espnow-pair/pair-20261015T152353-718612500Z/` |
| S3 COM37 ↔ C3 COM38, 1 × 64-byte payload | PASS | Both callbacks succeeded and the byte-identical echo returned; decoded Core frame was 68 bytes. `dev/evidence/espnow-pair/pair-20261015T152400-964459300Z/` |
| S3 COM37 ↔ C3 COM38, 100 × 240-byte payload | PASS | 100/100 byte-identical echoes; decoded Core frame was 244 bytes, below the 250-byte ESP-NOW v1 payload limit. The 263-byte encoded Stream R MTU is a separate bound and is not the packet size here. `dev/evidence/espnow-pair/pair-20261015T152646-142841800Z/` |
| S3 COM37 with C3 COM36/38/39 in one radio context, 1 probe per C3 | FAIL after two peers | COM36 and COM38 callbacks succeeded; COM39 receive and echo callback were followed by failed C3/S3 send callbacks. `dev/evidence/espnow-pair/four-peer-20261015T152657-650656300Z/` |

The contrast keeps COM39 as a board/radio-path issue for follow-up. These runs
remain unauthenticated Core codec smoke evidence; they do not test SEC-1,
`dmp_endpoint`, SAMPLE-1, or the authenticated multi-peer workload.

## Replacement C3 module and refreshed ESP-NOW smoke — 2026-10-15

During the 2026-10-15 runs, the operator replaced one C3 module. The device on
COM35 was treated as a separate physical unit from the earlier COM36/COM38/COM39 devices. Its observed
runtime identity is ESP32-C3 MAC `9c:cc:01:61:40:40`; the serial adapter is a
CH343 USB-UART bridge (USB serial `5C38020005`). It uses the dedicated C3 UART0
console image `build/espnow-pair-esp32c3-uart0-bridge/dmp_espnow_pair.bin`
(SHA-256
`15e33ba90049b735f4cf10389cb78664728062a3a64875d083ca5626ad7a05f6`).

| Scenario | Result | Evidence boundary |
|---|---|---|
| S3 COM37 ↔ replacement C3 COM35, 10 × 64-byte payload | PASS, 10/10 round trips | Unauthenticated Core echo; COM35 image path/hash and USB identity recorded in `dev/evidence/espnow-pair/pair-20261015T194024-422322400Z/run.json` |
| S3 COM37 with C3 COM36/COM38/COM35, 10 probes per peer | PASS, 30/30 round trips | One test-radio owner with three serialized unicast peers; COM35 has a distinct UART0 image entry in `dev/evidence/espnow-pair/four-peer-20261015T193853-624349900Z/run.json`; this is not `four_parallel` or an authenticated DMP endpoint |
| Intentional coredump on replacement C3 COM35 | PASS, panic/reboot, partition extraction, and offline symbolic decode | Read-only 1 MiB partition capture at `0x300000`; 6,270 non-erased bytes; 6,368-byte ELF with RISC-V machine type. Offline decode on 2026-10-16 used EIM ESP-IDF 6.1, esp-coredump 1.17.2, and GDB 17.1 to resolve the expected abort in `handle_command` at `main.c:542`. See `dev/evidence/espnow-pair/core-dump-esp32c3-COM35-20261015T193900-663174Z/{run.json,offline-decode.json}` |
| ESP-NOW host-stub regression suite | PASS, 31/31 | CI-safe runner/parser behavior only; no hardware or SEC-1 claim |

The pair/four-peer images report 256-byte decoded Core MTU, 263-byte encoded
Stream R MTU, and 250-byte ESP-NOW v1 payload maximum as separate limits. The
observed test frame was 68 bytes. These refreshed smoke results do not change
the P12/P01C/P25 status: they still do not exercise SEC-1, `dmp_endpoint`,
SAMPLE-1 persistence, or the authenticated `four_serial`/`four_parallel`
acceptance workload.

The remaining acceptance work requires physical ESP32-S3 and ESP32-C3 boards:

1. Repeat MCU-05 on each final board: three boot epochs × four `RUN 2 128`
   blocks per epoch (3,072 Noise pairs per board), balanced fixed/random
   NNpsk0/XX; two 100 ms UART-bridge EN pulses through RTS, keeping DTR
   inactive as the bridge requires. Capture
   ROM banner and POWERON reset reason, fresh boot IDs, reset counters, and
   allocation/heap/stack/synchronization/overlap checks. The prior S3 result
   predates this final code; prior C3 evidence did not complete this gate.
2. Run P01C's integrated endpoint workload on one endpoint with four
   authenticated peers under both `four_serial` and `four_parallel`; record
   actual heap/retained/scratch/stack limits and complete the protected
   4096-byte service-2 exchange. The current bench has one S3 and three C3
   units; reserve a fifth board so one endpoint can have four physical peers.
3. Exercise SAMPLE-1's actual NVS reserve/commit across warm reset and power
   loss, old-association closure before READ/publish/activate, commit failure,
   maximum-index epoch rollover, stale-result/TELEM rejection, and the limits
   of ordinary NVS against complete old-image restoration.
4. Record physical TRNG readiness/quality and any timing/energy measurements
   required by the existing P01C acceptance. Do not change eFuses.

Read-only COM35 inspection on 2026-10-16 identified the replacement module as
ESP32-C3 rev 0.4, MAC `9c:cc:01:61:40:40`, with 4 MiB flash. Its
`UART_PRINT_CONTROL=0b11` disables ROM output on UART; native USB Serial/JTAG
ROM output remains enabled (`DIS_USB_SERIAL_JTAG_ROM_PRINT=0b0`), but COM35 is
only a CH343 USB-UART bridge. No eFuse was changed. The replacement C3 was
flashed with the current MCU-05 image and completed six MCU-04 provider cases
plus one 1,024-pair MCU-05 epoch. The planned-reset gate observed a new boot ID
and reset counter but no UART ROM banner/reset-cause line, then stopped without
retry. See `dev/evidence/mcu05-20261016-COM35/summary.md` and its raw logs. The
three-epoch MCU-05 qualification remains incomplete until an observable native
USB Serial/JTAG ROM channel is connected. ARM ABI checks remain deferred by
owner direction, and non-Espressif physical qualification remains deferred.

## Package state

| Area | Recorded state | Scope boundary |
|---|---|---|
| P12 endpoint/SAMPLE-1 | Host software exercised; 34-row ledger remains 10 whole-row passed / 24 partial | The one-endpoint four-peer topology and both `four_serial`/`four_parallel` profiles pass, including a protected 4096-byte service-2 transfer. The separate two-attempt manifest, real authenticated wrong-sender case, transport ownership/lifecycle cases, and fail-closed epoch owner are covered in the current host suite. Primary evidence is 29 passed / 5 partial; the five primary-partial rows need target NVS/reset/UART evidence. Peer evidence remains 10 passed / 24 partial where the model does not implement real SEC-1 association behavior or the complete primary lifecycle. See the current closeout above. |
| P13–P20 | Accepted for their recorded package scopes | Each package's linked evidence remains authoritative; this summary does not expand its gate. |
| P21 independent peer | Owner-accepted for host/peer functionality | Historical actual-input/read-set and enforced access-boundary records are incomplete. |
| P22 mixed Stream R/packet binding | Done for host/simulation | No physical transport or MCU claim. Reviewed snapshot hash: `0D126BC55389C446496EA6EA213FE28D7F7E93AD3F8F4F119F9F7D7F275208FF`. |
| P23 C/Python interoperability | Done for enabled host/simulation scope | Historical accepted snapshot recorded full CTest 111/111 and peer suite 410 run, 408 passed, 2 skipped for documented sandbox/profile reasons. The latest owner-authorized non-ARM RBO gate passed all registered C/Python interop tests; ARM ABI/layout checks were excluded and remain pending. No physical binding or release claim. |
| P24 equivalent-workload benchmark | Done for host/simulation tooling | One-iteration correctness smoke; not a release-performance, energy, or physical-radio study. |
| P01 / P01C | Running / pending physical qualification | The finite host provider API/failure/secret-copy matrix and integrated endpoint topology are exercised. P01C still needs actual S3/C3 runtime, resource, entropy, reset, and persistence measurements. |
| P25 | Pending | Host and target compile/link gates are complete for this continuation. P25 remains open until selected S3/C3 physical acceptance; this report does not authorize a release. |

The current closeout above reports the full current host and compile/link gates.
The dated sections below preserve earlier focused and historical evidence.

## Current focused host evidence

- Protected SAMPLE-1/service-2 host selection:
  `ctest --test-dir build/host --output-on-failure -R
  "^endpoint\\.(sample_.*|protected_sample_.*|protected_service2_immediate)$"`
  passed 20/20.
- The focused A1 epoch endpoint case now also holds a service-2 RSP until after
  peer replacement and confirms the old-CID response fails authentication.
  `cmake --build build/host --target dmp_test_endpoint_sec --parallel 4` and
  `ctest --test-dir build/host -R '^endpoint\.protected_sample1_epoch_endpoint$'
  --output-on-failure` passed; this is host evidence and does not close the P12
  peer/interop rows.
- `security.handshake` passed 1/1 after adding
  `cached-flight-lifetime`, which checks the configured retransmission count,
  stable cached bytes, and cache invalidation at expiry. The test advances time
  between retries and verifies the original deadline after each successful
  retry; it also zero-initializes the session before the missing-fixture path.
  Independent GPT-6.1-sol High review found no remaining issue.
- P12's `protected_service2_immediate` verifies an SEC-1 service-2 REQ receives
  its immediate reliable RSP, followed by a result ACK and no separate request
  ACK. An authenticated request for disabled service 3 is rejected before the
  application callback. This uses a 64-byte opaque payload within manifest
  maxima; the 1,024-byte fragmented request/result is covered in P23.
- The latest focused P12 security run passed 7/7, including malformed
  correlated RSP rejection before receipt, valid and malformed fragmented
  SAMPLE-1 results, same-epoch reconnect rollback protection, and rejection of
  15/17-byte TELEM payloads at the SAMPLE-1 boundary. An optional result
  validator adds one callback pointer to the endpoint object; the current run
  is host-only and does not measure target RAM.
- P01 provider/handshake regressions passed their focused 2/2 CTests after
  independent review. They cover the `remote_public` closed-owner wipe
  exception, replay of the original cached AWAITING flight after caller RX
  mutation, and bounded retry/cache expiry. The latest provider-only follow-up
  adds DH allocation-failure cleanup and cipher child-capacity refusal with
  surviving-owner traffic; its focused `security.provider_adapter` CTest
  passed 1/1 and independent review found no issue. Other P01/P01C requirements
  remain open.
- The 2026-10-13 follow-up adds premature Noise hash-output recovery,
  short-read capacity wiping, and post-allocation constructor-cleanup assertions
  to `security.provider_adapter`, plus a one-peer endpoint-boundary test for
  both configured services, 256/257-byte encoded-core admission, and
  4096/4097-byte request admission. The focused provider and endpoint CTests
  passed; independent review found no actionable issue. These checks do not
  close the per-endpoint four-peer `four_parallel` row, prove a delivered
  4096-byte exchange, or establish target or physical behavior.
- A further provider case submits a 15-byte ciphertext to the live ChaChaPoly
  decryptor. It confirms the short-MAC `INVALID_LENGTH` path clears only the
  declared 32-byte output capacity, preserves the tail and resource accounting,
  and allows exact fixture decryption on the same cipher afterward. The focused
  provider CTest passed 1/1; independent review found no issue. This remains
  primitive-wrapper host evidence, not endpoint replay or target evidence.
- A second late-constructor case verifies XX private-static cleanup after
  prologue validation rejects the owner, followed by exact flight-1 recovery on
  the same provider. The provider CTest passed 1/1 and independent review found
  no issue. This does not claim full XX completion or exhaustive secret-copy
  erasure.
- A premature Split case confirms a fresh NNpsk0 owner rejects Split in its
  initial write phase, zeros both output wrappers without changing provider
  accounting, and then writes exact flight 1 on the same handshake. The
  provider CTest passed 1/1; independent review found no issue. It does not
  cover authenticated-read failures.
 - A previous full host CTest attempt did not complete: after the subprocess
  harness passed with workspace-local TEMP/TMP, the process-isolated minimal
  endpoint lifecycle test could not establish its host loopback peer and timed
  out. It was superseded by the completed RBO gate recorded below.

## Owner-approved continuation evidence — 2026-10-13

The current continuation adds exact implementation and test evidence for D1-D6.
The focused tests were built and passed on the current working tree before this
RBO retry was submitted:

- `cmake --build build-local-gcc --parallel 4` — passed.
- `ctest --test-dir build-local-gcc --output-on-failure -R
  "^(application.sample1_epoch_owner|security.handshake_transport|endpoint.protected_different_sender|endpoint.protected_multi_peer_routing|endpoint.protected_sample1_epoch_endpoint|endpoint.protected_sample_retry_two_attempts)$"` — 6/6 passed.
- The six cases cover the application-side epoch owner, integrated handshake
  transport lifecycle, another authenticated sender over real SEC-1 peers, one
  endpoint with four active/draining peers and shared result pressure, the
  protected epoch endpoint path, and the separate two-attempt manifest profile.
- The retry manifest
  `profiles/deployments/test-direct-sample-retry-2-nnpsk0.json` has SHA-256
  `56687ad71c6bd557a3629b35819e77576dcf551ddc53ff7cb3731b231aa8b294`; its
  validator reports a 263-byte encoded Stream R bound and timing/resource
  feasibility. Existing DIRECT-1 manifests remain unchanged.
- The multi-peer endpoint test proves routing/isolation, active/draining
  lifecycle and shared operation pressure. Its new regression prepares two
  local initiators before holding two inbound reads, then exercises four
  endpoint-total pending reservations, two occupied scratch slots, refusal and
  recovery, authenticated-candidate binding, and rejection of a fifth attempt
  under one endpoint-owned admission. RBO job
  `job_01M4VK50CRT9GJMARGB4BVJEGP` built `dmp_test_endpoint_sec` and passed
  `endpoint.protected_multi_peer_routing` 1/1. The wrapper runs both the
  `four_parallel` (two scratch slots) and `four_serial` (one scratch slot)
  lifecycle profiles. This is host concurrency evidence; it does not measure
  whole-endpoint target RAM or close the full host gate.

Earlier attempts to start a fresh full CMake/CTest run were canceled or could
not capture a snapshot. A later broad RBO host gate did run and is recorded
below; its failures do not close the gate.

## Previous broad host gate — 2026-10-13

RBO job `job_01M4VF3G79Y9083FA5PMNWB3QQ` built all 166 targets successfully;
CTest passed 115/142 and reported 27 failures. The recorded failing areas are
`security.handshake`, protected multi-peer routing and endpoint repair, peer
radio/R7 interop, P24 benchmark, retry-all and freshness scenarios, and endpoint
RAM lifecycle/report/layout checks. One radio endpoint lifecycle case timed
out. This is a failed broad host gate, not a pass inferred from compilation.
The focused SEC-1 drain regression ran later and passed
`endpoint.protected_rotation` and `endpoint.protected_drain` (2/2), but does
not substitute for the broad rerun. The exact failure output has since been
recovered. The multi-peer test failed first during fixture provider setup and,
after that fix, at an assertion that used inbound-only `abandon_request` for an
outbound request. Both test issues are corrected in the current dirty tree.
RBO job `job_01M4VK50CRT9GJMARGB4BVJEGP` rebuilt the endpoint security target
and passed the focused multi-peer test (1/1), which runs both crypto-slot
profiles. The broad gate has not yet been rerun; the 27-failure count remains
the last full-gate result, not a current-tree result.

The failures above are historical and were resolved in the newer host gate
below. Target qualification remains a separate final phase.

## P19 endpoint memory evidence

The process-isolated P19 harness measures host requested-byte high-water for
one endpoint. Remote-peer memory is excluded. These figures are not physical
MCU peaks.

| Profile | Manifest SHA-256 | Host requested-byte high-water | Reservation / cap |
|---|---|---:|---:|
| `TEST-DIRECT-MINIMAL-128` | `3bbcce998d664fa74970f503a39b28474de9291d453373810d641b2b662fb6e4` | 24,617 B | 38,167 / 131,072 B |
| `TEST-DIRECT-MINIMAL-256` | `4dc75347343c209c1ed12ab67e60eba83ff974beaa9f351c121da87e7b18b946` | 26,281 B | 39,959 / 131,072 B |
| `DIRECT-1` | `29f7895ab3f8dadfbe7331f1981fa35dcad2bec59139464e29bddc4e841e5285` | 36,265 B | 60,488 / 131,072 B |
| `RADIO-1` | `9767b5daff88424e64887dd78a335c4de0f9b93900d4512c1cec9c4d041b53a9` | 47,146 B | 66,340 / 131,072 B |

The RADIO-1 requested-byte high-water was refreshed on 2026-10-14 after the
packet-framing RX correction. RBO job `job_01M4VNT0DN9C77R7FV7JYVBYH4` passed
the lifecycle, measurement, merge and report checks 4/4. The three DIRECT
figures remain the earlier P19 measurements. The RADIO-1 manifest digest and
reservation are unchanged.

The earlier P19 RADIO-1 run delivered a 1,024-byte request in 32 fragments,
observed a retry, validated 80/80 routed frames, and checked the 21-byte S7
freshness grant/token binding. The measured provider retained peak was 1,477 B, retained
payload after handshake was 408 B, and the largest single allocation was
256 B. The 16,384 B scratch value is a single-allocation limit, not an additive
arena.

Still unknown or excluded: task-stack high-water, allocator metadata/alignment
on target, remote-peer memory, integrated whole-DMP target peaks, physical
runtime peaks, and energy. The measured reservations being below the declared
cap are useful planning evidence; they do not establish that a selected board
will run the complete workload.

## P24 benchmark evidence

Command:

```text
python tools/bench.py --modes nnpsk0,xx --sizes 64,256,1024 --iterations 1 --seed 9216 --output build/host/p24-matrix-smoke.json
```

The 12/12 runs used the actual C endpoint, independent Python peer, and two
simulated P23 relays, with a fresh SEC-1 association and S7 grant per run. All
six paired workload and payload digests matched. SELECTIVE-32 repaired one
missing fragment per size; retry-all repaired 2, 8, and 32 fragments for the
64/256/1,024-byte workloads. The protected selective runs emitted three
FRAG_STATUS frames; retry-all emitted none.

Cold setup virtual time was 27 ms and grant virtual time was 20 ms. Warm
exchange virtual time was 4,390–4,690 ms for SELECTIVE-32 and 2,382–2,967 ms
for retry-all. These are simulated schedule outputs, not wall latency or radio
timings. Host CPU/wall/RSS are diagnostics. Energy was not instrumented.
Endpoint executable SHA-256 recorded for this run:
`1e0e4f02c17185a85802ac6634608668eb9870c55b3ce34af3db44378452de68`.

| Profile | Manifest SHA-256 |
|---|---|
| NNpsk0 RADIO-1 | `9767b5daff88424e64887dd78a335c4de0f9b93900d4512c1cec9c4d041b53a9` |
| NNpsk0 retry-all | `bc8bba7c929c6d0fe9ad39dbe66a6699d342304ae8485ddf5cac9e32605b55f1` |
| XX RADIO-1 | `8ddf226f205ac3e547b57858d6cd68aa960fab03f6462b9f27cca81c0822fe60` |
| XX retry-all | `4aece0283e15774346dd2d0d73d45e8c496a4e91aec2ac2693a253e977c767c9` |

## P23 interop manifests

The accepted enabled interop scope pins nine manifest identities:

| Manifest | SHA-256 |
|---|---|
| `direct-nnpsk0.json` | `29f7895ab3f8dadfbe7331f1981fa35dcad2bec59139464e29bddc4e841e5285` |
| `direct-xx.json` | `075e8ed25f6011c7dc20c84789eb61dff4784af86413415ddbd4aede07bcfce3` |
| `radio-nnpsk0.json` | `9767b5daff88424e64887dd78a335c4de0f9b93900d4512c1cec9c4d041b53a9` |
| `radio-xx.json` | `8ddf226f205ac3e547b57858d6cd68aa960fab03f6462b9f27cca81c0822fe60` |
| `test-radio-retry-all-nnpsk0.json` | `bc8bba7c929c6d0fe9ad39dbe66a6699d342304ae8485ddf5cac9e32605b55f1` |
| `test-radio-retry-all-xx.json` | `4aece0283e15774346dd2d0d73d45e8c496a4e91aec2ac2693a253e977c767c9` |
| `test-peer-tcp-stream-r-nnpsk0.json` | `ae409bc0d46cda319f9e9861dcc3fbc6922d2ee6d35155ae61c329b79dc497cc` |
| `test-peer-tcp-stream-r-sample20-nnpsk0.json` | `514db4ae41fd8b2b1f4b4b7361cfb63e4b04ea095f33948f0e17e5a19bad9e2f` |
| `test-mixed-tcp-stream-r-sim-packet-nnpsk0.json` | `64363ad7c1f750409bad1b039509cfec4037a981fa760bbb4dce57bb50e5546d` |

The P23 matrix records 53 applicable interop rows passing; 84 other normative
rows are explicitly outside the interop slice and retain their separate
primary/peer status. P23 does not prove that those underlying requirements
passed by implication.

## P21 provenance limitation

The owner accepted P21 host/peer functionality so P23 could proceed. Available
historical records do not include complete actual input/read inventories for
P21A–D or enforced filesystem access boundaries; the checkout cannot reconstruct
them. This is an evidence gap, not evidence that source was reused. The
independent implementations also share the published protocol/model context,
so the review is not formally clean-room. No clean-room or complete
independence claim is made.

## Historical open-item snapshot (superseded by the 2026-10-15 closeout above)

The entries below preserve the state at their recorded dates. The 2026-10-15
closeout above is the current status for host/software gates and exact physical
residuals.

- The 137-row normative ledger now links exact primary, peer, profile and
  interop test symbols. The last row-level reconciliation recorded 74 passed, 62 partial and 1
  not-run; mapping the 27 later broad-gate failures to normative rows is
  pending. The separately recorded P23 interop axis has 53 applicable rows
  with concrete test references and 84 rows outside that matrix. The row-level
  counts and limits are in [`DMP_Normative_Cases.md`](DMP_Normative_Cases.md).
  A test reference or package status does not close the entire normative row.
- D1 multi-peer behavior is implemented for one endpoint with peer routing,
  isolation, shared quotas and active/draining lifecycle. Focused RBO CTest now
  proves four endpoint-total pending reservations and two occupied crypto
  scratch slots under endpoint-owned admission. The same CTest wrapper passes
  both declared `four_serial` and `four_parallel` lifecycle profiles. This is
  host scenario evidence; provider/endpoint target RAM and physical runtime
  remain separate requirements.
- D2 adds an independently hashed two-attempt SAMPLE-1 test profile and
  protected retry scenario. The base DIRECT-1 manifests are preserved.
  Dependent P19 retry-profile/RAM evidence still needs current-snapshot
  revalidation in the full host gate.
- D3 rejects a well-formed correlated SAMPLE-1 result from another authenticated
  SEC-1 peer and checks that the designated producer remains routed. The focused
  `endpoint.protected_different_sender` CTest passed 1/1.
- D4 adds the production handshake-to-transport adapter around the existing
  Noise state machine. The focused `security.handshake_transport` CTest passed
  1/1 for per-peer synchronization and COPY/BORROW, BUSY, delayed/uncertain
  completion, cancellation, expiry and stale-callback cases.
- D6 adds the SAMPLE-1 application-side epoch owner with storage and lifecycle
  ports, outside the payload-agnostic core. The host composition orders epoch
  reservation, old-association closure, READ, publication and activation, and
  stops on uncertain storage/lifecycle outcomes. Target-backed durable storage
  and reset/rollback qualification remain for the final hardware phase.
- P01 remains open for the integrated endpoint resource row, the finite provider
  failure/secret-copy inventory, aggregate resources and target qualification.
  P01C will qualify the selected ESP32-S3/C3 scope at the end of the plan;
  non-Espressif physical qualification stays deferred and its requirements
  remain recorded. No host result closes target or physical requirements.
- At the time of the earlier canceled job, RBO reported no online agent. The previous Bash job was canceled before
  execution, and a zsh replacement could not be captured. The owner directed us
  to wait for RBO; no local full-gate run has been substituted. P25 remains pending until a green post-fix host gate, evidence/status
  reconciliation and independent review are complete, followed by the
  scheduled hardware gate.

The prior P12 table is superseded by the continuation results above. Durable
target persistence remains distinct from the host application-owner behavior;
wrong-sender rejection and retry scheduling now have direct host tests. P12 row
status remains 28 passed / 6 partial until the fresh gate and independent review
justify a row-by-row update.

## Reproduction and linked evidence

- P19 measurements and manifest identities: [`DMP_Recovery_Matrix.md`](DMP_Recovery_Matrix.md).
- P21 provenance disposition: [`DMP_P21_acceptance_plan_2026-10-12.md`](DMP_P21_acceptance_plan_2026-10-12.md).
- P22/P23 evidence and final review: [`DMP_P22_plan_2026-10-12.md`](DMP_P22_plan_2026-10-12.md), [`DMP_P23_plan_2026-10-12.md`](DMP_P23_plan_2026-10-12.md).
- P24 benchmark command, comparison rules and results: [`DMP_P24_plan_2026-10-12.md`](DMP_P24_plan_2026-10-12.md).
- P12/P01 continuation and final hardware sequence: [`DMP_P12_P25_completion_plan_2026-10-12.md`](DMP_P12_P25_completion_plan_2026-10-12.md), [`p01-reconciliation.md`](evidence/noise-mcu-soak-20260927/p01-reconciliation.md).
- Normative row-to-test references and result axes: [`DMP_Normative_Cases.json`](DMP_Normative_Cases.json) and [`DMP_Normative_Cases.md`](DMP_Normative_Cases.md).
- Separate two-attempt SAMPLE-1 profile: [`test-direct-sample-retry-2-nnpsk0.json`](../profiles/deployments/test-direct-sample-retry-2-nnpsk0.json).

P25 should remain pending until the remaining required software gates are
resolved or explicitly dispositioned and P01C has completed. This report does
not declare the DMP implementation ready for production or guaranteed to run
on hardware.

## P01 provider OOM follow-up — 2026-10-13

Additional host regressions cover first-allocation failures in DH public-key,
DH shared-secret, and cipher construction, plus handshake registration failure
at actual provider child-table capacity. The provider adapter build and focused
CTest passed 1/1; an independent GPT-6.1-sol High review found no actionable
issue. These named host cases do not establish exhaustive cleanup, aggregate
four-peer resources, endpoint/MCU memory, or physical operation. Hardware
qualification remains a final-phase gate.

## P01 endpoint transport boundary follow-up — 2026-10-13

`endpoint.protected_transport_reject_retry` now proves the endpoint wrapper
preserves an admitted request after a pre-accept transport `BUSY` and forwards
an accepted `DMP_TX_POSSIBLY_TRANSMITTED` completion as an unknown outcome at
revocation. The host endpoint and P23 interop suites passed. This does not
exercise a production handshake-flight submission path; cached handshake
transport integration, aggregate resources, and hardware qualification remain
open.

## P01 cipher short-capacity recovery follow-up — 2026-10-13

`security.provider_adapter::output-contract` now exercises a live cipher
encrypt call whose declared capacity is below the backend's minimum. It checks
`DMP_PROVIDER_INVALID`, zero output length, wiping of exactly the declared
three-byte capacity, preservation of the tail sentinel, and unchanged provider
resource accounting. The same cipher then encrypts the exact NNpsk0 PN0 fixture;
the Noise backend rejects before encryption and nonce advancement. Provider
build was current, focused `security.provider_adapter` CTest passed 1/1, and
independent review found no actionable issue. This is primitive-wrapper host
evidence only; endpoint PN allocation, target runtime, physical operation, and
P01C remain open.

## P01 handshake wrong-phase recovery follow-up — 2026-10-13

`security.provider_adapter::wrong-phase-handshake-output` exercises read in
WRITE_MESSAGE and write in READ_MESSAGE on the same NNpsk0 initiator. Each
Noise `INVALID_STATE` is mapped to `DMP_PROVIDER_INVALID`; the adapter zeros
output length, wipes exactly the declared 64-byte capacity, preserves the tail
sentinel and provider accounting, and retains a usable handshake. The same
owner then emits exact Flight 1 and accepts exact Flight 2 payload. Provider
build was current, focused `security.provider_adapter` CTest passed 1/1, and
independent review found no actionable issue. This proves live wrong-action
guard behavior in the host provider adapter only; fatal post-read handling,
endpoint integration, target runtime, physical operation, and P01C remain open.

## P01 closed-wrapper output follow-up — 2026-10-13

`security.provider_adapter::closed-wrapper-output` closes a live NNpsk0
handshake and cipher, then exercises their invalid-handle paths. Read, write,
hash, Split, encrypt, and decrypt return `DMP_PROVIDER_INVALID` without
changing caller outputs; `remote_public` also returns INVALID and zeros its
32-byte output. The wrappers remain erased and provider resource accounting
does not change. Provider build and focused `security.provider_adapter` CTest
passed 1/1; independent review found no actionable issue. This is closed-handle
host boundary evidence only; operational Noise failure paths, endpoint
lifecycle/concurrency, complete secret-copy inventory, target runtime, physical
operation, and P01C remain open.

## P01 fatal handshake write-capacity follow-up — 2026-10-13

`security.provider_adapter::handshake-write-short-capacity-fatal-cleanup`
passes a one-byte capacity to a fresh NNpsk0 initiator's valid Flight 1 write.
The pinned Noise backend reports `INVALID_LENGTH` and moves that owner to
FAILED; the adapter returns `DMP_PROVIDER_INVALID`, zeros the length, and wipes
only the declared byte. A repeated write is rejected, and closing the failed
owner erases/releases its state. A newly opened handshake on the same provider
then emits exact Flight 1. Provider build and focused CTest passed 1/1;
independent review found no actionable issue. This is one host fatal-write
branch only; it does not establish all Noise failure semantics or target
qualification.

## P01 late key-validation cleanup — 2026-10-13

`security.provider_adapter::late-key-validation-cleanup` covers three
post-allocation NNpsk0 constructor guards: invalid local ephemeral length,
invalid PSK length after valid ephemeral installation, and NULL PSK with a
32-byte length. Each failure erases its wrapper and released allocations,
balances allocation/release accounting, leaves no live or retained blocks,
and is followed by exact Flight 1 recovery on the same provider. Provider build
and focused `security.provider_adapter` CTest passed 1/1; independent review
found no actionable issue. This is limited to these constructor paths and does
not establish a complete handshake, exhaustive secret-copy cleanup, or target
qualification.

## P01 XX NULL static-key constructor cleanup — 2026-10-13

`security.provider_adapter::xx-null-static-validation-cleanup` checks the XX
initiator guard for NULL local static key with length 32 after Noise and
ephemeral allocation. The failed wrapper and released blocks are erased,
allocation/release accounting balances, and live/retained counts return to
zero. A subsequent valid owner on the same provider emits exact fixture Flight
1 and closes cleanly. Provider build was current, focused CTest passed 1/1,
and independent review found no actionable issue. This covers one constructor
branch and host recovery only; it does not close the full XX exchange,
provider-wide cleanup inventory, or target qualification.

## P01 constructor key-presence matrix — 2026-10-13

`security.provider_adapter::constructor-key-presence-matrix` adds six
NNpsk0/XX initiator validation cases for NULL ephemeral, omitted required PSK,
short XX static key, omitted required XX static key, unexpected NNpsk0 static
key, and unexpected XX PSK. All six fail after Noise allocation, erase the
wrapper and released state, balance accounting, and recover with exact fixture
Flight 1 on the same provider. Provider build was current, focused CTest passed
1/1, and independent review found no actionable issue. This does not close the
full handshake, exhaustive provider failure inventory, or target qualification.

## P01 cipher input-over-capacity recovery — 2026-10-13

`security.provider_adapter::cipher-encrypt-input-over-capacity` gives the
adapter four plaintext bytes and a three-byte output capacity. Noise rejects
the oversized input before checking space for its MAC. The test verifies
INVALID, zero output length, an exact three-byte wipe with the tail preserved,
unchanged resource accounting, then exact fixture PN0 recovery on the same
cipher. Provider build was current, focused CTest passed 1/1, and independent
review found no actionable issue. This remains host provider-boundary evidence;
it does not establish endpoint transport or target behavior.

## 2026-10-14 — Integrated four_parallel RBO verification

The endpoint-owned shared-admission regression covers four endpoint-total
pending attempts while two real asynchronous reads occupy the configured
scratch slots. It checks refusal without losing pending work, scratch recovery,
authenticated candidate binding, and fifth-attempt rejection. Independent
GPT-6.1-sol High review found no actionable issue after correcting the fixture
provider ownership and the outbound request cleanup call.

RBO job `job_01M4VK50CRT9GJMARGB4BVJEGP` built
`dmp_test_endpoint_sec` with AppleClang 21.0.0.21000101 and passed
`ctest --test-dir build/host --output-on-failure -R
'^endpoint\\.protected_multi_peer_routing$'` (1/1). This CTest invokes both
the `four_parallel` (two scratch slots) and `four_serial` (one scratch slot)
profiles. The build emitted one Apple linker warning about duplicate static
libraries. `git diff --check --ignore-submodules=all --
tests/endpoint/test_endpoint_sec.c` passed. The broad host gate remains open;
no local full build/test or hardware action was performed.

## Earlier ARM-inclusive RBO host gate — 2026-10-14

RBO job `job_01M4VNEW5PSA337VT0PA715CMY` (snapshot
`snp_01M4VNEWDFEZSR3CAFGBQ5P2VN`) completed the host configure and build. CTest
ran 142 cases: 135 passed and 7 failed. Every failure was a profile RAM layout
check: `memory.direct-nnpsk0.layout`, `memory.direct-nnpsk0-async.layout`,
`memory.radio-nnpsk0.layout`, `memory.radio-nnpsk0-n2.layout`,
`memory.test-radio-retry-all-nnpsk0.layout`,
`memory.test-direct-minimal-128.layout`, and
`memory.test-direct-minimal-256.layout`. Each reports that the MCU layout lacks
the required endpoint/provider/peer records.

The Cortex-M ABI report contains no required records because the RBO worker does
not provide `arm-none-eabi-gcc`. `memory.mcu_abi` currently exits successfully
when that compiler is unavailable, so its 1/1 result is not cross-compile
evidence. The dependent layout checks remain unresolved. By the owner's later
direction, ARM ABI/layout checks are deferred; the subsequent non-ARM gate
explicitly excludes the ABI probe and these seven layout cases and is recorded
below. This 142-case run remains an ARM-inclusive historical attempt with
seven failed layout checks. The other 135 cases passed, including all
registered P23 C/Python interop tests. Neither run establishes physical
behavior.

The follow-up RADIO-1 refresh, RBO job
`job_01M4VNT0DN9C77R7FV7JYVBYH4`, passed the endpoint lifecycle, measurement,
merge and report checks 4/4. It measured 47,146 B requested-byte high-water for
one host endpoint with the unchanged RADIO-1 manifest digest. This excludes peer
memory, target allocator overhead/alignment, stack high-water and physical MCU
peak.

## Normative test-reference audit — 2026-10-14

The source audit checked all 137 JSON ledger rows and all 510 linked test
references: 317 primary C, 112 independent-peer, 4 profile-validator and 77
interop references. Every referenced file exists and contains its named test
symbol (zero missing references). This verifies the crosswalk only. It does not
prove the test body covers every normative subcase or convert test execution
into a whole-row pass. Whole-row counts remain 74 passed, 62 partial and 1
not-run pending explicit row-by-row disposition; P21 retains its owner-accepted
provenance caveat.

## Non-ARM host and ESP32 compile/link gate — 2026-10-14

RBO job `job_01M4VXMPM95Q2AR8ZER5D091KM` (snapshot
`snp_01M4VXMPXC9BDN5X3Z462R7E6Z`) ran the final dirty checkout on the macOS
arm64 worker. The native host configuration and build succeeded. CTest was run
with `-E '^(memory\.mcu_abi|memory\..*\.layout)$'`: 134 tests passed, 0
failed. This explicitly excludes the Cortex-M ABI test and its seven dependent
profile layout checks; those results remain deferred, not passed. The remaining
native suite, including P12 endpoint/security and P23 interop tests, passed.

The ESP-IDF 6.1 compile/link-only probes also succeeded for
`tests/embedded/esp32s3` (`IDF_TARGET=esp32s3`) and
`tests/embedded/esp32c3` (`IDF_TARGET=esp32c3`). They compile and link the
portable library and SAMPLE-1 probe apps; no board was flashed or run. The logs
include Apple linker duplicate-library warnings and ESP-IDF component include
validation warnings; all requested commands exited successfully.

The final focused continuation selection also passed 4/4:
`endpoint.protected_sample1_epoch_endpoint`,
`endpoint.protected_transport_reject_retry`, `security.handshake_transport`,
and `application.sample1_epoch_owner`. Independent GPT-6.1-sol High review of
the current source changes found no actionable findings; the reviewer did not
run tests.

This gate does not refresh the 34 P12 whole-row dispositions or the 137-row
ledger by itself. Current recorded counts remain P12 28 passed / 6 partial and
the normative ledger 74 passed / 62 partial / 1 not-run pending concrete
row-by-row review. P01 provider failure/secret-copy mapping, complete normative
disposition review, target durable storage, and final S3/C3 physical
qualification remain open. The owner has directed that ARM checks be revisited
later; they are not a current blocker to continuing native and ESP32 software
work.

## Historical physical ESP-NOW and coredump evidence — 2026-10-15

At the time of these runs, the bench was identified as ESP32-S3 rev 0.2 on COM37 (4 MiB flash,
MAC `20:6e:f1:b0:f0:2c`) and ESP32-C3 rev 0.4 on COM35, COM36, and COM38
(each 4 MiB flash; MACs `9c:cc:01:61:40:40`, `28:37:2f:75:5d:64`, and
`18:8b:0e:31:be:9c`, respectively). COM35 used a CH343 UART0 bridge; COM36
and COM38 exposed USB Serial/JTAG. The S3 and the three C3 devices ran the
isolated ESP-NOW smoke image. COM39 was not enumerated during
those runs.

The S3/C3 pair runner passed 10/10 echoes at 64-byte payloads (68-byte Core
frames) and 10/10 at 240-byte payloads (244-byte Core frames). The four-board
runner passed 30/30 serialized round trips through one S3 radio context and
three distinct C3 peers, with 10/10 per peer at both payload sizes. The
post-restore 64-byte run also passed 30/30. Evidence is under
`dev/evidence/espnow-pair/pair-20261015T214755-454939700Z/`,
`pair-20261015T214811-702451100Z/`,
`four-peer-20261015T214947-926509300Z/`,
`four-peer-20261015T214958-266852200Z/`, and
`four-peer-20261015T215548-042217200Z/`; each contains raw serial streams,
timestamped event timelines, commands, and `run.json` with image hashes.
The measured limits remain separate: decoded Core MTU 256 bytes, Stream R
encoded MTU 263 bytes, and ESP-NOW v1 payload maximum 250 bytes. A 244-byte
Core frame fits the radio packet limit; this smoke did not send a full 256-byte
Core frame or a 263-byte Stream R frame.

The physical coredump smoke passed on C3 COM35 and S3 COM37 after an explicit
test abort and application reboot. Each 1 MiB coredump partition at `0x300000`
contained a length-prefixed ELF; the extracted ELF sizes were 6,368 bytes
(C3) and 16,352 bytes (S3). Both dumps decoded successfully with ESP-IDF 6.1
and `espcoredump.py v1.15.0`; the backtraces identify the intentional
`CORE_DUMP_TEST` abort in the test application. Captures and decoder logs are
in `core-dump-esp32c3-COM35-20261015T214817-920311Z/` and
`core-dump-esp32s3-COM37-20261015T215006-049835Z/`. This proves the test-image
partition, capture, extraction, and offline decoder path; it is not a claim
about a production crash policy.

Image hashes recorded by the runners: S3 app
`c82abbf9f3b4e7ddc347c4c57ec42325f60811a4884f1c3196f19cb7da3d0ffd`, C3
native USB Serial/JTAG app
`2d2dcf3e2a8a39fee15a2e5bca14f34f2d9bcdbccf7053e7d53e076f0e838905`, and C3
UART0/CH343 app
`15e33ba90049b735f4cf10389cb78664728062a3a64875d083ca5626ad7a05f6`.
The provider image was temporarily loaded on COM36 for MCU-05, but its UART0
console did not match that board's USB Serial/JTAG interface; the run failed
before HELLO, any workload, or reset. COM36 was restored to the ESP-NOW image,
then the four-board 64-byte smoke passed again. On COM35, the earlier MCU-05
run completed one epoch (1,024 Noise pairs) and failed closed after its planned
reset because the board's read-only eFuse configuration disables ROM output
on UART; this remains partial evidence. No eFuse was changed.

These are physical radio/Core-codec and test-image coredump results only. The
radio test is unauthenticated and does not run SEC-1, `dmp_endpoint`, SAMPLE-1,
the one-endpoint authenticated four-peer behavior, or `four_parallel`.
P12's host implementation remains covered by the prior host gate; P12 target
storage/reset/secure-UART rows, P01C resource/entropy/transport/persistence
qualification, and final P25 acceptance remain open.

The CI-safe host regressions were rerun after the physical tests:

```text
python -m unittest discover -s tests/host/espnow_pair -p 'test_*.py' -v  # 31/31
python -m unittest discover -s tests/provider/parallel -p 'test_serial*.py' -v  # 32/32
python -O -m unittest discover -s tests/provider/parallel -p 'test_serial*.py' -v  # 32/32
python -m py_compile tests/embedded/espnow_pair/serial_pair.py tests/embedded/espnow_pair/serial_four.py tests/embedded/espnow_pair/serial_coredump.py tests/provider/parallel/serial_parallel.py tests/provider/parallel/serial_soak.py tests/provider/parallel/test_serial_parallel.py tests/provider/parallel/test_serial_soak.py  # exit 0
```

Review-fix revalidation on 2026-10-16 added a current-C3 default-port regression
and strict provider partition-table parser cases. The updated host suites passed
32/32 ESP-NOW stub tests and 37/37 provider tests in both normal and optimized
Python modes. These host results do not imply physical COM40 behavior.

The physical serial runners remain outside CTest. Host stubs never open COM
ports and do not imply hardware, SEC-1, or endpoint evidence.
