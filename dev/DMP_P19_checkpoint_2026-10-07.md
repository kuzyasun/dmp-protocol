# P19 checkpoint — 2026-10-07

## Snapshot

- Repository: `C:\projects\gemslibe\dmp-protocol`
- Branch / published base before this continuation: `feat/initial-version` at `b9b0b56050bd2b97a453bd25a77e76cc1b102c21` on `origin/feat/initial-version`.
- P19 acceptance commit: `46be3ca89bbba75e03dff6fef16f2a314bbc45f9`, pushed to `origin/feat/initial-version`.
- P19 was committed and pushed as noted above. Changes in the 2026-10-08 continuation remain uncommitted and unpushed; no commit or push was requested for them.
- RAM worker `/root/ram_tooling` completed the manifest-bound process-isolated lifecycle harness under `tests/memory/`. After two reviewer-identified evidence defects were fixed, coordinator build and CTest pass 2/2; final focused independent review found no actionable findings. Earlier pre-fix lifecycle outputs remain invalid.
- P19 is accepted for its host/simulation scope after the full host gate and final independent review. The approved routes used were GPT-6-Luna High for implementation and GPT-6.1-sol High for independent review.

## Completed step

- Fixed TEST-RADIO-N2 from an invalid 128-byte path to an exact 119-byte path. At MTU 128 a protected 64-byte service-2 body fits in one frame, so that manifest could not demonstrate N=2. The 119-byte manifest passes offline validation; RADIO-1 and retry-all manifests are unchanged. Its exact digest is `46ef7a08f2b6caf53d13d7c2c900e522c87286af313e49a70f5249a077fb7376`.
- Corrected the N=2 geometry/async expectations. The 64-byte payload emits exactly two 32-byte fragments; loss of index 0 yields missing mask `0x01` and repairs only index 0.
- Extended `scenarios.r6` `r6-all-loss`: after all eight initial slices are lost, probe index 7 is admitted, status mask `0x7f` repairs indices 0–6, the receiver accepts once, and the sender receives its ACK with no unknown outcome.
- The separate initial-phase probe constructs one real `dmp_endpoint` with libdmp and the P01B provider for minimal 128- and 256-byte profiles. Its reported caller-owned endpoint bundle is `10,096` requested bytes and provider state is `1,328` requested bytes; provider retained current/peak/largest-allocation are `0` bytes. Keep these host-requested values distinct from lifecycle measurements and MCU evidence.
- Manifest RAM charge totals are reservations after the 2026-10-08 owner-directed reconciliation: minimal-128 `38,167` bytes, minimal-256 `39,959`, DIRECT-1 `60,488`, RADIO-1 `66,340`; the region cap remains `131,072` bytes. Lifecycle high-water is recorded below; charges and measurements are separate.
- Added async TEST-RADIO-N2 one-slot exhaustion/result-before-repair-completion and fragmented-RSP/FRAG_STATUS overlap. The independent read-only follow-up found no issues in those scenarios.
- Added endpoint-origin TTL=0 and narrow-egress refusal/cache-preservation cases; existing relay tests cover integrity-only CRC recomputation and missing on-wire CONTEXT. Independent review found no issue in the TTL=0/narrow-egress assertions.
- At the time this checkpoint was first written, remaining matrix rows still needed source/evidence reconciliation; subsequent dated sections below record the added checks and current open P21D/P22/P23/physical boundaries.

## Continued after push

- Reconciled additional matrix rows from the current named tests: service-2 freshness, routed host relay traffic, reliable DATA/EVENT, fragmented result loss and duplicate requests, authenticated feedback identity mismatch, and the distinct-key second-association check.
- At the time of this earlier entry, fragmented RSP/FRAG_STATUS overlap, PN/SEQ boundaries, explicit endpoint origin TTL 0, CRC after TTL mutation, and narrower egress remained open; later dated sections below record the added coverage. Independent peer remains P21D, case 11 remains P22/P23, and physical radio is not claimed.
- Independent review of `e173b3a` found a best-effort fragmented-frame admission defect. The coordinator fixed it by probing a full-size slice before SEQ allocation/admission; the 99-byte/chunk-98 regression, targeted geometry build/CTest, and read-only follow-up review all pass.
- `ctest --test-dir build/host --output-on-failure -R "^scenarios\.(freshness|relay_sample|feedback|r7)$"` — 4/4 passed.
- `ctest --test-dir build/host --output-on-failure -R "^(scenarios\.(async|gaps)|identity\.profile_admit)$"` — 3/3 passed.
- Added async TEST-RADIO-N2 one-slot exhaustion plus result-before-repair-completion coverage in `scenarios.async_radio`; the build and focused CTest passed.
- `cmake --build build/host --target dmp_test_recovery_gate --parallel 2` — passed after the geometry fix.
- `ctest --test-dir build/host --output-on-failure -R "^scenarios\.geometry$"` — 1/1 passed.

## Verification

- `python -B tests/profiles/test_deployments.py` — 14/14 passed.
- `python tools/validate_profile.py --expect-sha256 46ef7a08f2b6caf53d13d7c2c900e522c87286af313e49a70f5249a077fb7376 profiles/deployments/radio-nnpsk0-n2.json` — valid; derived encoded frame 119 bytes and establishment traffic 1,666 bytes.
- `cmake --build build/host --target dmp_test_recovery_gate --parallel 2` — passed.
- `ctest --test-dir build/host --output-on-failure -R "^scenarios\.(geometry|r6|async_radio)$"` — 3/3 passed.
- `cmake --build build/host --target dmp_test_recovery_gate dmp_test_relay --parallel 2` — passed after the async/route additions.
- `ctest --test-dir build/host --output-on-failure -R "^(scenarios\.(async_radio|relay_sample)|relay\.transparent)$"` — 3/3 passed.
- `ctest --test-dir build/host --output-on-failure -R "^scenarios\.async_radio$"` — 1/1 passed after fragmented-RSP overlap was added.
- `cmake --build build/p19-ram-endpoint-gcc --target dmp_ram_endpoint_initial --parallel 4` — passed.
- `ctest --test-dir build/p19-ram-endpoint-gcc -V -R "^memory\.test-direct-minimal-(128|256)\.endpoint_initial$"` — 2/2 passed with the values above.
- `git diff --check` — passed before the final documentation/checkpoint edits; rerun before the next handoff.
- The first sandboxed CMake regeneration was denied access to Windows system temp. A workspace-local temp was rejected by the checked-Sodium script because it is inside the Git worktree. The successful host build used the approved build escalation for that temporary write.

## Later gates and boundaries

- P19 is accepted for its host/simulation scope. Its six-phase endpoint RAM lifecycle and full-profile RADIO-1 freshness/route path are detailed below; MCU runtime peaks and physical transport are not claimed.
- P21D owns independent-peer recovery/routing coverage. P22/P23 own the multi-binding S10 case 11. Physical MCU peaks and transport remain separate evidence gates.
- The user authorized committing and pushing the reviewed P19 package. Do not flash hardware or integrate this library into DTrack.

## Current continuation state — 2026-10-08

P19's owner-directed profile/resource reconciliation is complete. The two minimal DIRECT profiles now meet `sender_slots >= 2 * service_count = 4`; endpoint association charges cover pending + active + draining slots. The validator also checks nonzero component reserves, the full bootstrap reserve and encoded-frame control/adapter minima. Seven NNpsk0 manifest hashes are synchronized across `profiles/deployments/digests.json`, the P20 frozen brief and the P19 lifecycle digest pins.

Current host requested-byte lifecycle high-water remains minimal-128 24,617 B, minimal-256 26,281 B, DIRECT-1 36,265 B and RADIO-1 42,146 B. Reservations are 38,167/39,959/60,488/66,340 B under the unchanged 131,072-byte region cap. RADIO-1 measured 80/80 routed frames valid and verified its 21-byte freshness grant/token binding. These are process-isolated host payload-request measurements and manifest reservations; stack high-water, allocator metadata/alignment, peer memory and physical MCU peaks remain unmeasured.

P20 and P21A are accepted. The P21A peer suite passes 33/33; its final independent review found no actionable code findings and confirmed the exact frozen manifest hashes and schema copy. Eight findings across the codec/manifest/Stream R package are closed with regression coverage. P21B direct delivery/reassembly is the next dependency-ready step and has not started.

Validation after the profile/resource correction:

- RBO profile suite — 27/27 (`job_01M4C3XHKZ8GY3M41NBNSX2VSJ`).
- RBO P21A peer suite — 33/33 (`job_01M4C40G805DZVN807HMEZRH0K`).
- RBO RAM-report suite — 27/27 (`job_01M4C40XN839EC7YQVXA2ES2AX`).
- `cmake --build build/p19-ram-endpoint-gcc --target dmp_ram_endpoint_process --parallel 4` — passed.
- `ctest --test-dir build/p19-ram-endpoint-gcc --output-on-failure -R endpoint_lifecycle` — 4/4 passed with local peer IPC access.
- Focused provider measurement, merge, report, layout and MCU ABI CTest — 17/17 passed.

Routine Python suites were run through the available RBO Agent Broker command jobs. The exposed broker tools in this session did not provide a separate Antigravity coding-agent dispatch route. No commit, push, hardware flash, or DTrack integration was made for this continuation. Preserve existing changes and the `build/p19-ram-endpoint-gcc` evidence when resuming at P21B.

## Historical P19 work log entries (2026-10-07)

## 2026-10-07 — Endpoint SEQ exhaustion boundary

`tests/scenarios/recovery_gate.c` now adds `seq-exhaustion-endpoint` to `scenarios.gaps`. The test injects the terminal SEQ value into one active authenticated endpoint identity, emits a protected TELEMETRY frame carrying `UINT32_MAX`, then confirms repeated telemetry polls and a reliable REQ fail with `DMP_LIMIT_EXHAUSTED`, without a frame, live sender, or wrap. This is a boundary injection rather than a run through all 2^32 values.

- `cmake --build build/host --target dmp_test_recovery_gate --parallel 2` — passed.
- `ctest --test-dir build/host --output-on-failure -R "^scenarios\.gaps$"` — 1/1 passed.
- Direct `gaps` scenario output reported `seq-exhaustion-endpoint`, `pn-limit-receive-guard`, and `gaps` as passing.
- `git diff --check` — passed with only line-ending notices.
- The first independent review found that `take_queue` could hide an extra frame when called with capacity 1; the scenario now asserts the wire queue count is exactly 1 before draining. Rebuild and CTest passed again, and the read-only follow-up confirmed the counterexample is closed with no new findings; the reviewer did not rerun tests.

At the time of this SEQ boundary handoff, `sel-r7-pn-seq` remained partial for want of a valid authenticated frame near PN 2^24; the next section records that follow-up. Recovery-specific invalid-profile behavior, independent final review, and the applicable host gate remain open. P19 is still running and unaccepted.

## 2026-10-07 — Valid SEC-1 PN boundary

Added the isolated `scenarios.pn_limit` CTest. The harness advances the real active SEC-1 send counter by sealing every intervening record, reseals an endpoint-origin TELEMETRY at PN `0xFFFFFF`, and delivers it to the peer endpoint. The peer returns `DMP_OK` with no AEAD failure. A header-only PN `2^24` mutation with its stale tag is rejected without increasing the AEAD failure counter; the endpoint's next telemetry poll returns `DMP_LIMIT_EXHAUSTED` and the send counter stays at `2^24`.

- `cmake --build build/host --target dmp_test_recovery_gate --parallel 2` — passed.
- `ctest --test-dir build/host --output-on-failure -R "^scenarios\.pn_limit$"` — 1/1 passed in 38.27 seconds.
- `build/host/Testing/Temporary/LastTest.log` records `pn-valid-max-and-send-limit ... outcome=pass`.

The 16M intermediate records are real SEC-1 seals but are not delivered; only the valid max-PN frame is received. This is host endpoint evidence, not an MCU or physical transport run. The PN/SEQ row is now closed for the covered cases. Recovery-specific invalid-profile behavior, RAM accounting, independent final review and the applicable host gate remain open; P19 remains running and unaccepted.

## 2026-10-07 — Static recovery-profile admission boundary

Strengthened `scenarios.r6` `r6-mtu`: an otherwise admitted SELECTIVE-32 RADIO profile with `return_mtu=0` returns `DMP_UNSUPPORTED`, retains both configured SELECTIVE-32 modes and leaves the caller's admitted output unchanged. Existing `identity.profile_admit` checks invalid R3 timing combinations and a valid boundary tuple. Normative R1 fixes recovery mode before traffic and forbids changes during an association, so live policy mutation is not a supported API case; admission rejection is the applicable recovery-specific gate.

- `cmake --build build/host --target dmp_test_recovery_gate dmp_test_profile_admit --parallel 2` — passed.
- `ctest --test-dir build/host --output-on-failure -R "^(scenarios\\.r6|identity\\.profile_admit)$"` — 2/2 passed.
- `git diff --check` — passed with only Git line-ending notices.

At this checkpoint, the `sel-r7-profile` row had closed, while full-profile RAM, final review and the full host gate remained open. The continuation below records the closure work.

## 2026-10-07 — Full RADIO-1 and minimal endpoint RAM lifecycle

Extended the process-isolated harness to exercise the exact `radio-nnpsk0.json` bytes/digest and admitted RADIO-1 configuration, including a real S7 service-0 grant, fresh service-2 token, endpoint-origin routed frames, reliable 1,024-byte request/result, a lost frame with fresh-PN retry, cleanup and a fresh reconnect. The harness records actual initiator/responder traffic epochs and excludes the peer process from the measured endpoint. The manifest-bound minimal-128 and minimal-256 profiles now report all six lifecycle phases as well.

Host requested-byte results (includes caller-owned state and provider retained high-water; excludes peer, allocator metadata/alignment and stack high-water):

- `RADIO-1` (`fe18d3c7...40a36`): 40,669 B caller-owned current; 42,146 B lifecycle high-water; provider retained peak 1,477 B. Service 2 transferred 1,024-byte request/result in 32 fragments with a fresh-PN retry; 80/80 route frames were valid, and the 21-byte freshness grant/token binding passed.
- `DIRECT-1` (`d541555e...c77f7`): 36,265 B lifecycle high-water; 1,024-byte request/result in 16 fragments with retry.
- `TEST-DIRECT-MINIMAL-128` (`e0a9ac98...ac831`): 19,466 B high-water; one-frame 128-byte exchange with retry.
- `TEST-DIRECT-MINIMAL-256` (`d64c6ee6...d7ef`): 20,362 B high-water; four-fragment 256-byte exchange with retry and one exact peer assembly.

Thus measured host requested-byte high-water is 22,680 B lower for minimal-128 and 21,784 B lower for minimal-256 than RADIO-1. This comparison is workload-specific host evidence, not MCU or physical savings. Provider retained charge was corrected from 1,325 to 1,477 B in RADIO-1, TEST-RADIO-N2 and TEST-RADIO-RETRY-ALL manifests; dependent exact-byte digests/fixtures/checks were synchronized. Reservations remain 32,590/33,614 B for minimal-128/256, 53,154 B DIRECT-1 and 59,035 B RADIO-1 under the unchanged 131,072 B cap. Compile-only MCU layout is separate; MCU stack/dynamic peak, allocator metadata/alignment and physical runtime peak remain unknown.

The follow-up fixes the independent review's two findings: the reconnect capture now selects and reparses only `DMP_TYPE_DATA`; RAM report/layout reject lifecycle evidence whose profile ID or exact manifest SHA-256 differs. The recovery matrix's live arrival-gap row also has `collection-window-receive-gap` coverage.

Validation on the corrected snapshot: deployment Python tests 14/14; contract Python tests 11/11; RAM report Python tests 26/26; full CMake build passed; focused lifecycle/recovery CTest 5/5; full CTest 97/97 passed with access to Windows `%TEMP%` for `harness.subprocess`; `git diff --check` passed. RADIO runtime JSON verifies stale `DMP_TYPE_DATA` is rejected as `DMP_AUTHENTICATION_FAILURE` without dispatch. The final independent review found no actionable code findings and did not rerun tests. Its documentation note about the matrix row referred to an earlier version; the current row names `collection-window-receive-gap` and records the passing 1,500 ms receive-gap check. P19 is accepted for its host/simulation scope. P21D independent-peer coverage, P22/P23 case 11, MCU runtime peaks and physical transport remain out of scope.
