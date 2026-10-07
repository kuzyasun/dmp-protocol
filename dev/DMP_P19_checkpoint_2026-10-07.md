# P19 checkpoint — 2026-10-07

## Snapshot

- Repository: `C:\projects\gemslibe\dmp-protocol`
- Branch / published base: `feat/initial-version` at `0918802` on `origin/feat/initial-version`.
- The user authorized that commit and push. Subsequent matrix, work-board and execution-log reconciliation is in the current working tree; check `git status` before resuming.
- RAM worker `/root/ram_tooling` completed the manifest-bound process-isolated lifecycle harness under `tests/memory/`. After two reviewer-identified evidence defects were fixed, coordinator build and CTest pass 2/2; final focused independent review found no actionable findings. Earlier pre-fix lifecycle outputs remain invalid.
- P19 remains `running`, not accepted. The approved routes remain GPT-6-Luna High for implementation and GPT-6.1-sol High for independent review.

## Completed step

- Fixed TEST-RADIO-N2 from an invalid 128-byte path to an exact 119-byte path. At MTU 128 a protected 64-byte service-2 body fits in one frame, so that manifest could not demonstrate N=2. The 119-byte manifest passes offline validation; RADIO-1 and retry-all manifests are unchanged. Its exact digest is `46ef7a08f2b6caf53d13d7c2c900e522c87286af313e49a70f5249a077fb7376`.
- Corrected the N=2 geometry/async expectations. The 64-byte payload emits exactly two 32-byte fragments; loss of index 0 yields missing mask `0x01` and repairs only index 0.
- Extended `scenarios.r6` `r6-all-loss`: after all eight initial slices are lost, probe index 7 is admitted, status mask `0x7f` repairs indices 0–6, the receiver accepts once, and the sender receives its ACK with no unknown outcome.
- The separate initial-phase probe constructs one real `dmp_endpoint` with libdmp and the P01B provider for minimal 128- and 256-byte profiles. Its reported caller-owned endpoint bundle is `10,096` requested bytes and provider state is `1,328` requested bytes; provider retained current/peak/largest-allocation are `0` bytes. Keep these host-requested values distinct from lifecycle measurements and MCU evidence.
- Manifest RAM charge totals remain reservations: minimal-128 endpoint `32,590` bytes; minimal-256 endpoint `33,614` bytes. The region cap remains `131,072` bytes. These initial-phase values are not lifecycle peaks or MCU measurements.
- Added async TEST-RADIO-N2 one-slot exhaustion/result-before-repair-completion and fragmented-RSP/FRAG_STATUS overlap. The independent read-only follow-up found no issues in those scenarios.
- Added endpoint-origin TTL=0 and narrow-egress refusal/cache-preservation cases; existing relay tests cover integrity-only CRC recomputation and missing on-wire CONTEXT. Independent review found no issue in the TTL=0/narrow-egress assertions.
- Other recovery-matrix rows still require a complete source/evidence reconciliation.

## Continued after push

- Reconciled additional matrix rows from the current named tests: service-2 freshness, routed host relay traffic, reliable DATA/EVENT, fragmented result loss and duplicate requests, authenticated feedback identity mismatch, and the distinct-key second-association check.
- Kept unsupported claims partial/open: fragmented RSP/FRAG_STATUS overlap, a valid PN near 2^24 and SEQ wrap, explicit endpoint origin TTL 0, CRC after TTL mutation, narrower egress, independent peer, and physical radio.
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

## Remaining acceptance work

- Reconcile the accepted host lifecycle evidence into remaining accounting dependencies. The harness pins each manifest digest into config and handshake profile hash, uses distinct deterministic entropy for a fresh reconnect handshake, checks changed initiator/responder traffic epochs and rejection of the old protected DATA frame, and passes full-size 128/256-byte REQ loss/retry. It requires no assembly for the one-frame 128 case and one 256-byte assembly from four fragments for the 256 case. Its result payload is 17 bytes, not the profile's maximum. Focused independent RAM review found no actionable findings. The earlier pre-fix lifecycle metrics are invalid. No full-profile endpoint RAM run, MCU ABI/map/runtime peak, or physical peak is established. Keep the `131,072` cap and do not treat host sizes as MCU evidence.
- Remaining recovery rows include a valid PN near 2^24, endpoint SEQ exhaustion/wrap, and recovery-specific invalid-profile behavior. S10 case 11 stays with P22/P23; independent peer and physical radio also remain later gates.
- Independent follow-up review found no issue in the fragmented-RSP/status overlap or the TTL=0/narrow-egress assertions. Full P19 final review and the applicable full host gate remain pending; close the remaining matrix rows and corrected RAM/accounting checks before any P19 acceptance.
- Do not flash or integrate into DTrack. The initial P19 package is already pushed; confirm current Git state before publishing any later checkpoint.

## Resume point

Read this checkpoint, `dev/DMP_Recovery_Matrix.md`, `dev/DMP_Work_Packages.md`, and the P19 owner direction in `dev/DMP_Correction_Plan.md`. Check live agent status, current Git state and test artifacts. Finish independent review of the corrected RAM harness, reconcile its host-only metrics and any findings, then close the remaining PN/SEQ/profile rows and final gate. Keep the recorded build directories and permission-protected temp directories intact.
