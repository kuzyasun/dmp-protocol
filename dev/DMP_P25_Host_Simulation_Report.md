# P25 host and simulation readiness report — 2026-10-13

## Status and conclusion

This report consolidates the accepted host/simulation evidence available for
P25. It is not a release approval. P25 remains pending because P12, the P01
acceptance umbrella, and P01C target qualification are still open. Physical
hardware checks are intentionally scheduled after the software and report
gates, per owner direction. Host memory estimates and provider-only MCU
measurements do not guarantee whole-device operation.

The P21 peer work is accepted for functional host evidence under the owner's
explicit disposition, with an unresolved historical provenance caveat. No
clean-room or complete-independence claim is made.

## Package state

| Area | Recorded state | Scope boundary |
|---|---|---|
| P12 endpoint/SAMPLE-1 | Running; 28 passed / 6 partial among 34 primary rows | Host and SEC-1 evidence. Remaining rows include durable epoch storage, production association-transition integration, and profile-dependent retry scheduling. |
| P13–P20 | Accepted for their recorded package scopes | Each package's linked evidence remains authoritative; this summary does not expand its gate. |
| P21 independent peer | Owner-accepted for host/peer functionality | Historical actual-input/read-set and enforced access-boundary records are incomplete. |
| P22 mixed Stream R/packet binding | Done for host/simulation | No physical transport or MCU claim. Reviewed snapshot hash: `0D126BC55389C446496EA6EA213FE28D7F7E93AD3F8F4F119F9F7D7F275208FF`. |
| P23 C/Python interoperability | Done for enabled host/simulation scope | Full registered CTest 111/111 on the accepted snapshot; peer suite 410 run, 408 passed, 2 skipped for documented sandbox/profile reasons. No physical binding or release claim. |
| P24 equivalent-workload benchmark | Done for host/simulation tooling | One-iteration correctness smoke; not a release-performance, energy, or physical-radio study. |
| P01 / P01C | Running / deferred | Provider host gaps and complete target/physical acceptance remain open. |
| P25 | Pending | This evidence report does not close dependencies or authorize a release. |

The current working tree includes further P12 and P01 host regressions beyond
the earlier accepted P23/P24 snapshots. The focused results below apply to the
current host build; the historic package totals above are not a claim that the
entire current CTest inventory was rerun.

## Current focused host evidence

- Protected SAMPLE-1/service-2 host selection:
  `ctest --test-dir build/host --output-on-failure -R
  "^endpoint\\.(sample_.*|protected_sample_.*|protected_service2_immediate)$"`
  passed 20/20.
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
- A recent full host CTest attempt did not complete: after the subprocess
  harness passed with workspace-local TEMP/TMP, the process-isolated minimal
  endpoint lifecycle test could not establish its host loopback peer and timed
  out. Therefore the current full CTest suite is not reported green.

## P19 endpoint memory evidence

The process-isolated P19 harness measures host requested-byte high-water for
one endpoint. Remote-peer memory is excluded. These figures are not physical
MCU peaks.

| Profile | Manifest SHA-256 | Host requested-byte high-water | Reservation / cap |
|---|---|---:|---:|
| `TEST-DIRECT-MINIMAL-128` | `3bbcce998d664fa74970f503a39b28474de9291d453373810d641b2b662fb6e4` | 24,617 B | 38,167 / 131,072 B |
| `TEST-DIRECT-MINIMAL-256` | `4dc75347343c209c1ed12ab67e60eba83ff974beaa9f351c121da87e7b18b946` | 26,281 B | 39,959 / 131,072 B |
| `DIRECT-1` | `29f7895ab3f8dadfbe7331f1981fa35dcad2bec59139464e29bddc4e841e5285` | 36,265 B | 60,488 / 131,072 B |
| `RADIO-1` | `9767b5daff88424e64887dd78a335c4de0f9b93900d4512c1cec9c4d041b53a9` | 42,146 B | 66,340 / 131,072 B |

The RADIO-1 run delivered a 1,024-byte request in 32 fragments, observed a
retry, validated 80/80 routed frames, and checked the 21-byte S7 freshness
grant/token binding. The measured provider retained peak was 1,477 B, retained
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

## Open software and final qualification gates

- P12 now has six partial primary rows. The current known gaps include
  production durable SAMPLE-1 epoch storage and fail-stop behavior, a production
  adapter that couples epoch rollover to closure of old associations, a
  wrong-authenticated-sender negative case, and protected initialization retry
  scheduling under a profile that permits more than one attempt. The three
  result/association ordering rows now pass under the endpoint's documented
  serialized-call contract; this is not evidence for concurrent calls from
  multiple threads. The protected host case also invalidates the old READ
  designation on association replacement, preserves the sample as an
  unsynchronized cache, and requires a new designated READ to resynchronize.
- P01 host evidence still lacks the declared `four_parallel` four-peer /
  four-pending / two-crypto-slot resource scenario and exhaustive buffer
  ownership/failure output reconciliation. Recent provider OOM/capacity tests
  cover only their named branches. `cached-flight-lifetime` checks the provider
  retry ceiling, cache stability, absolute deadline and expiry; the new
  `endpoint.protected_transport_reject_retry` checks pre-accept BUSY and an
  accepted uncertain completion through the endpoint wrapper. The production
  handshake owner still has no `dmp_transport` submission path, so its cached
  flight send-fault lifecycle remains open. Source inspection confirms that
  `dmp_reliability` rejects profiles where `peers != 1`, while `dmp_endpoint`
  stores one active and one draining association. The declared sensitivity
  counts are per endpoint, so four separate endpoints or the existing direct-
  Noise worker test cannot close the four-peer resource row. Closing it requires
  an owner decision on multi-peer endpoint scope; the manifest's `mtu_bytes`
  also needs an explicit mapping to endpoint `encoded_mtu` before that bound is
  treated as the same quantity.
- P01C remains open for integrated target RAM/stack measurements, hardware
  entropy and energy evidence, the C3 reset diagnostic gate, and a selected
  non-Espressif board/runtime. The final hardware phase must use explicitly
  selected boards, ports and bindings; no eFuse or irreversible board action
  is authorized by this report.
- The earlier full CTest host run remains incomplete due the sandbox loopback
  limitation described above. Re-run an appropriate complete host gate after
  software edits and environment access are settled.

The six remaining P12 primary rows stay partial for distinct reasons; none is
counted as a pass by P23 peer or interop results:

| P12 row | Remaining evidence | Next gate |
|---|---|---|
| `s-a1-epoch` | The host persistence port is deterministic test scaffolding; no production durable epoch store exists. | Implement the selected production storage adapter and qualify durable commit/failure behavior in P01C. |
| `s-a1-epoch-transition` | Sample epoch selection and generic rotation are separate tests; no production owner serializes READ, publication, activation, and closure of every old-epoch association. | Define and implement the production transition owner, then test its ordering and failure behavior. |
| `s-a2-designated-read` | Protected timeout and supersession are covered, but DIRECT-1 permits one initialization attempt, so retry scheduling is absent. | Preserve the one-attempt policy or authorize a profile revision and revalidate its hash and dependent evidence. |
| `s-a3-negative` | Wrong service, status, and payload lengths are rejected; a wrong authenticated sender/association is not exercised in the single-peer profile. | Add an authorized multi-peer test profile/fixture or retain this as outside the active profile. |
| `s-a4-restart` | Epoch reservation and association-closure callbacks remain host stubs. | Implement production persistence/closure adapters and qualify restart behavior in P01C. |
| `s-a4-persistence` | Durable target commit, rollback/counter-loss diagnostics, and production fail-stop behavior are unverified. | Complete the production storage/fail-stop path and the P01C target qualification. |

## Reproduction and linked evidence

- P19 measurements and manifest identities: [`DMP_Recovery_Matrix.md`](DMP_Recovery_Matrix.md).
- P21 provenance disposition: [`DMP_P21_acceptance_plan_2026-10-12.md`](DMP_P21_acceptance_plan_2026-10-12.md).
- P22/P23 evidence and final review: [`DMP_P22_plan_2026-10-12.md`](DMP_P22_plan_2026-10-12.md), [`DMP_P23_plan_2026-10-12.md`](DMP_P23_plan_2026-10-12.md).
- P24 benchmark command, comparison rules and results: [`DMP_P24_plan_2026-10-12.md`](DMP_P24_plan_2026-10-12.md).
- P12/P01 continuation and final hardware sequence: [`DMP_P12_P25_completion_plan_2026-10-12.md`](DMP_P12_P25_completion_plan_2026-10-12.md), [`p01-reconciliation.md`](evidence/noise-mcu-soak-20260927/p01-reconciliation.md).

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
