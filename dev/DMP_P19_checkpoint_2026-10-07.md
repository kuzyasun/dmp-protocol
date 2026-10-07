# P19 checkpoint — 2026-10-07

## Snapshot

- Repository: `C:\projects\gemslibe\dmp-protocol`
- Branch / published base: `feat/initial-version` at `e173b3a` on `origin/feat/initial-version`.
- The user authorized that commit and push. Subsequent matrix, work-board and execution-log reconciliation is in the current working tree; check `git status` before resuming.
- RAM worker `/root/ram_tooling` completed the initial-phase measurement and is now implementing the process-isolated lifecycle measurement under `tests/memory/`.
- P19 remains `running`, not accepted. The approved routes remain GPT-6-Luna High for implementation and GPT-6.1-sol High for independent review.

## Completed step

- Fixed TEST-RADIO-N2 from an invalid 128-byte path to an exact 119-byte path. At MTU 128 a protected 64-byte service-2 body fits in one frame, so that manifest could not demonstrate N=2. The 119-byte manifest passes offline validation; RADIO-1 and retry-all manifests are unchanged. Its exact digest is `46ef7a08f2b6caf53d13d7c2c900e522c87286af313e49a70f5249a077fb7376`.
- Corrected the N=2 geometry/async expectations. The 64-byte payload emits exactly two 32-byte fragments; loss of index 0 yields missing mask `0x01` and repairs only index 0.
- Extended `scenarios.r6` `r6-all-loss`: after all eight initial slices are lost, probe index 7 is admitted, status mask `0x7f` repairs indices 0–6, the receiver accepts once, and the sender receives its ACK with no unknown outcome.
- RAM measurement harness constructs one real `dmp_endpoint` with libdmp and the P01B provider for the minimal 128- and 256-byte profiles. Initial-phase outputs for both: caller-owned endpoint bundle requested/allocated `10,096` bytes; provider state requested `1,328` bytes; provider retained current/peak/largest-allocation `0` bytes. Provider allocator accounting matches `dmp_provider_retained()`.
- Manifest RAM charge totals remain reservations: minimal-128 endpoint `32,590` bytes; minimal-256 endpoint `33,614` bytes. The region cap remains `131,072` bytes. These initial-phase values are not lifecycle peaks or MCU measurements.
- Updated only the corresponding full-loss, delayed-status, N=2, and work-board notes. Other recovery-matrix rows still require a complete source/evidence reconciliation.

## Continued after push

- Reconciled additional matrix rows from the current named tests: service-2 freshness, routed host relay traffic, reliable DATA/EVENT, fragmented result loss and duplicate requests, authenticated feedback identity mismatch, and the distinct-key second-association check.
- Kept unsupported claims partial/open: R7 no-slot and fragmented result/status overlap, a valid PN near 2^24 and SEQ wrap, explicit endpoint origin TTL 0, CRC after TTL mutation, narrower egress, independent peer, and physical radio.
- Independent review of `e173b3a` found a best-effort fragmented-frame admission defect. The coordinator fixed it by probing a full-size slice before SEQ allocation/admission; the 99-byte/chunk-98 regression, targeted geometry build/CTest, and read-only follow-up review all pass.
- `ctest --test-dir build/host --output-on-failure -R "^scenarios\.(freshness|relay_sample|feedback|r7)$"` — 4/4 passed.
- `ctest --test-dir build/host --output-on-failure -R "^(scenarios\.(async|gaps)|identity\.profile_admit)$"` — 3/3 passed.
- `cmake --build build/host --target dmp_test_recovery_gate --parallel 2` — passed after the geometry fix.
- `ctest --test-dir build/host --output-on-failure -R "^scenarios\.geometry$"` — 1/1 passed.

## Verification

- `python -B tests/profiles/test_deployments.py` — 14/14 passed.
- `python tools/validate_profile.py --expect-sha256 46ef7a08f2b6caf53d13d7c2c900e522c87286af313e49a70f5249a077fb7376 profiles/deployments/radio-nnpsk0-n2.json` — valid; derived encoded frame 119 bytes and establishment traffic 1,666 bytes.
- `cmake --build build/host --target dmp_test_recovery_gate --parallel 2` — passed.
- `ctest --test-dir build/host --output-on-failure -R "^scenarios\.(geometry|r6|async_radio)$"` — 3/3 passed.
- `cmake --build build/p19-ram-endpoint-gcc --target dmp_ram_endpoint_initial --parallel 4` — passed.
- `ctest --test-dir build/p19-ram-endpoint-gcc -V -R "^memory\.test-direct-minimal-(128|256)\.endpoint_initial$"` — 2/2 passed with the values above.
- `git diff --check` — passed before the final documentation/checkpoint edits; rerun before the next handoff.
- The first sandboxed CMake regeneration was denied access to Windows system temp. A workspace-local temp was rejected by the checked-Sodium script because it is inside the Git worktree. The successful host build used the approved build escalation for that temporary write.

## Remaining acceptance work

- The initial RAM phase does not measure a bound SEC-1 association, NNpsk0 handshake, active steady state, protected request/result, loss/retry, cleanup or reconnect. No independent peer process/IPC harness exists yet; those lifecycle phases remain `not_measured` and RAM checks must keep failing closed.
- No full-profile endpoint RAM run, MCU ABI/runtime/map result, or physical peak is established. Do not raise the `131,072` cap or treat host sizes as MCU evidence.
- Finish the remaining recovery-matrix rows, especially R7 no-slot/result overlap, exact PN/SEQ wrap, explicit origin TTL 0, CRC-after-TTL, and narrower egress. S10 case 11 stays with P22/P23.
- Follow-up review confirmed the geometry fix and found no new issue in that diff; full P19 final review and the applicable full host gate remain pending. Complete the isolated-peer, one-device lifecycle RAM phases and dependent charges/hashes, then close remaining recovery rows before any P19 acceptance.
- Do not flash or integrate into DTrack. The initial P19 package is already pushed; confirm current Git state before publishing any later checkpoint.

## Resume point

Read this checkpoint, `dev/DMP_Recovery_Matrix.md`, `dev/DMP_Work_Packages.md`, and the P19 owner direction in `dev/DMP_Correction_Plan.md`. Check live agent status, current Git state and test artifacts. Continue the lifecycle RAM harness with its isolated peer/provider, then finish the remaining recovery rows. Keep the recorded build directories and permission-protected temp directories intact.
