# P03 deployment freeze

Status: P03 accepted by the coordinator; offline development/test scope only.

## Accepted outputs and checks

- [Six deployment manifests](../../../profiles/deployments/README.md), exact-byte
  SHA256 catalog and portable expected interpretations. Direct Stream R,
  RADIO-1 and distinct TEST-RADIO-RETRY-ALL each have NNpsk0/XX variants. Recursive
  comparison permits only family identity, recovery and probe/status differences.
- Per-endpoint 77440 direct / 81280 radio RAM reserves within 131072 bytes;
  each relay 29440 within 65536. Resource rationale pins historical provider
  inputs, counts physical backing/metadata separately from live peaks, and
  explicitly reserves unmeasured future modules. No measured MCU fit claim.
- [137 planned cases](../../DMP_Normative_Cases.md): 31 main 22.8, 24 S10 subcases
  spanning all 18 source cases, 10 R6, 16 R7, 24 SAMPLE A1-A4, 26 wire/vector
  rows, two Stream R policy rows and four unsupported-feature rejection rows.
  Every implementation status is `not-run`; the gate accepts the mapping only.
- Final `ctest.log` / `ctest.xml`: **3/3**, including **23 profile test methods**.
  Six deployment instances and their exact digests pass. Existing P02 corpus
  (41 invalid mutations, 17 raw cases and three fixtures), SEC-1 public fixture
  verifier and unchanged C11 scaffold also pass. `test-run.json` records command,
  versions and local fallback. No new C build was needed for P03.
- [Early independent Astra review](early-review.md) closed the confirmed Stream R
  timeout/reset-policy gap and found no COBS/reference contradiction. The
  coordinator verified actual profile/test arithmetic and diffs; see
  [calculations and limits](calculations.md). Additional final reviewer invocation
  hit the agent-thread limit and is not represented as an independent pass.

Coordinator review also corrected the R7 ledger's shifted columns, accounted for
the two binding rows, kept S10.17 restart policy in P13 and activation in P14,
and distinguished codec-only plaintext vectors from admitted SEC-1 traffic.
`ledger-check.json` records field/count/reference/ownership checks; no future
test was counted as run. Auxiliary source-text hashes normalize CRLF to LF for
portable checkout comparisons, while original source hashes are retained in
`resource-input-raw.json`. PROFILE_HASH never uses that normalization.

`checks.json` captures accepted input/code hashes. `final-check.json` verifies
the baseline HEAD and exact Git index and the bounded changed-file set. Initial
and intermediate test runs are retained alongside final logs. Existing changes
were preserved; no stage/commit/push/hardware/DTrack operation occurred.

Next: P04 creates the actual `libdmp` target and minimal core/framing/transport/
harness interfaces; P05-P07 implement and test those same library sources.

## Work and acceptance plan

1. Preserve the current checkout/index in `baseline.json` and ignored
   `build/profile-freeze-preserve/`. Reuse accepted P02; do not rerun provider
   experiments or claim unimplemented endpoint behavior.
2. Freeze six complete instances: DIRECT-1, RADIO-1 and the separately named
   TEST-RADIO-RETRY-ALL family, each with NNpsk0 or XX. Declare conservative
   portable development reserves, measured provider inputs and unmeasured module
   reservations. Radio comparison instances share every common workload,
   schedule, resource and deadline field.
3. Enumerate normative cases and future primary/peer/interoperability ownership.
   Planned tests start as `not-run`; deferred or unsupported work is not a pass.
4. Independently review the manifest contract, COBS vectors and full/protected
   reference rules before P04. Verify each finding before changing anything.
5. Check exact-byte digests, validation, comparison equality and traceability;
   inspect the actual diff and independent review, then update the work board.

The coordinator owns profiles, resource decisions, integration and acceptance.
Luna xhigh owns only `dev/DMP_Normative_Cases.{json,md}`. Astra xhigh performs the
early read-only contract/vector review. No more than two agents run concurrently.
RBO returned no live agents; profile checks use the announced local fallback.

## Evidence limits

These profiles select host simulation parameters, not a physical radio/stream
binding or measured whole-DMP MCU fit. The initial ESP32 evidence is an input,
not a portability restriction. P04/P08/P12/P15/P19 must reconcile actual code
with the same ceilings; P01C separately qualifies physical targets. No
commit, push, index mutation, firmware operation or DTrack integration is part
of this gate.
