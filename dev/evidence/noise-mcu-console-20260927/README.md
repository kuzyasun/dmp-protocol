# MCU-02 serial-controlled provider bench

Status: host tests and both MCU builds accepted after independent review.
Physical execution subsequently completed with owner authorization; see
[physical results](physical/README.md) for 80 paired scenarios and measured
heap/stack/timing. Independent physical-evidence review passed within this
serialized UART provider scope; P01 remains running.
P01 remains running. Baseline: parent 0072f61, fork c40f2dc, clean index/tree.

Owner supplied ESP32-S3 COM23 and ESP32-C3 COM35 and requires installed EIM /
ESP-IDF 6.1. EIM selected version and idf.py version were verified; both serial
ports enumerate as UART bridges. This does not identify the actual chips or flash
capacity. Prepare binaries and review before any deployment decision.

Plan: freeze private command protocol; implement portable bounded command core,
thin ESP-IDF UART/entropy/measurement adapter and Python scenario/log runner;
test host processes and negative parsing/fault/lifetime paths; compile both chip
targets using EIM 6.1; inspect maps/configuration and independently review the
fixed snapshot. Then resolve explicit board flashing authorization and run serial
scenarios with raw logs, firmware identities and resource/time measurements.

Coordinator owns security/state/lifetime, root build/target registration and
acceptance. Worker may own only Python client/tests against the frozen protocol.
No DMP endpoint/radio/interoperability gate is claimed. No secret export, flash
encryption, secure boot, eFuses or DTrack integration. UART is diagnostic/control;
Python-forwarded provider bytes are not ESP-NOW/Bluetooth transport evidence.
Both Espressif ABIs are useful; non-Espressif runtime remains a separate gate.

See tests/provider/console/PROTOCOL.md. Executable logs are evidence only after
commands actually run; host values never substitute for MCU measurements.

## Executed checks

Final RBO job `job_01M3G6TPFDE1DBWXH773A3Q0J7`, snapshot
`snp_01M3G6TPQ5YH851PPNEMFEKCZ3`, succeeded with exit 0. Exact commands are in
`remote-validation.sh`; `validation-summary.json` records identities and results.
Builds ran on the available macOS arm64 RBO agent with EIM's explicit `v6.1`
selector. The local installation was separately checked as ESP-IDF v6.1.

- Full host CTest: **33/33 PASS**, AppleClang 21. Includes 37 actual-process
  parser/lifetime/fault commands, 20 Python client unit tests and 16 two-process
  handshake pairs (NN/XX, fixed/random, both role orientations, two cycles).
- Live host trace: 679 responses. Expected negative results include 64 bad
  tag/AAD failures, 32 reused-TX-PN rejections, one setup OOM, one entropy failure
  and one invalid-state continuation after that entropy failure. No automatic
  mutation retry. Every successful lifetime returns to empty arena accounting.
- ESP32-S3 and ESP32-C3: fresh complete ESP-IDF v6.1 builds; ESP GCC 15.2.0,
  `esp-15.2.0_20251204`. No compiler warning/error matches in the saved build logs.
  Existing archive/ELF symbol gates passed for both images: custom allocation
  and checked entropy hooks, required provider symbols, no forbidden legacy RNG
  symbols in the ELF. See per-target reports and raw symbol logs.
- Coordinator verified all 47 packaged artifact SHA-256 values. Host and both
  MCU builds carry source fingerprint
  `71e3a2d6f1a77ce124ea402eded20bcb44aee34c6a23de5007bd41e67a791086`.
  `source-hashes.json` records normalized source bytes. Actual binary hashes and
  configuration/compiler evidence remain separate from this fingerprint.

Images are retained locally in ignored `build/mcu02-final/build/bench-esp32s3/`
and `build/mcu02-final/build/bench-esp32c3/`, including bootloader, partition table,
application, flasher arguments, ELF and map. The RBO bundle artifact is
`art_01M3G6WXY5EJ705B0CD7ZVYRYD`, SHA-256
`ef497340361db66b8bf0575630f3b8181d50d2df5e5739fbd799582ec5860b5f`.
RBO materialize rejected the current destination configuration; the already
collected local controller cache was copied and verified against artifact hashes.
No generated binary or SDK output was hand-edited.

## Corrected findings

Earlier failures are retained, not presented as passes:

1. Host `-Werror` found signed comparison in reply-size checking; fixed the type.
2. The real-process entropy-fault test found raw platform error 1; the Noise hook
   now translates failure to `NOISE_ERROR_SYSTEM`, matching the checked API.
3. First IDF link failed because platform callbacks were in an already-scanned
   main archive. Their object now belongs to the provider's rescan group.
4. Full macOS tests exposed MEM-03's create-versus-complete admission assumption.
   The 8192-byte mixed cases admit three pending contexts but only two complete;
   one Split safely refuses. The probe reports this, verifies exact OOM/null
   outputs/preserved counters/guard survival/cleanup and keeps medium/large full
   completion mandatory. No quota or provider behavior changed. All 36 updated
   sensitivity cases are in `macos-sensitivity-results.json`; previous Windows
   values remain Windows evidence.
5. Independent source review found early slot-operation errors reported action
   0 instead of the surviving owner's state. A common epilogue now reports the
   actual state; real-process checks cover premature Split, bad payload,
   failed-entropy continuation and reused TX PN.

## Physical handoff (pre-deployment record)

Recommended next step is owner-authorized identification and deployment on
COM23 (S3) and COM35 (C3), followed by the short one-cycle serial run documented
in [the bench guide](../../../tests/provider/console/README.md). Identification
must confirm chip and at least the configured 4 MiB flash before writing the
bootloader/partition/application offsets from each target's flasher arguments.
Keep all generated hashes/configuration with the physical trace. Remote CMake
caches contain remote paths; do not reuse them as local IDF build directories.

The linked application files are 206160 bytes (S3) and 187984 bytes (C3).
`esp32s3-size.json` and `esp32c3-size.json` report whole lab-image sections,
including SDK and harness overhead. These are not provider-only budgets or
runtime free-heap/stack measurements. Physical startup, UART behavior, RNG
availability, timing, heap/stack high-water and repeated lifetimes remain pending.
RF/ESP-NOW/Bluetooth, non-Espressif runtime, parallel owners and full DMP endpoint
memory/admission remain separate open gates. P01 is not complete.

## Pre-flash acceptance

Independent read-only reviewer `mcu_console_review` (GPT-6 Astra, max) confirmed
19 reviewed file hashes, 33/33 host tests, 37 core checks, 20 client unit tests,
16 paired scenarios, 32 reused-TX-PN refusals with COMPLETE and no trace failures
or timeouts, and both IDF 6.1 builds without compiler warning/error diagnostics.
The action finding was closed; the narrow MEM-03 delta had no remaining findings.
Reviewer ran no tests, writes or hardware operations; it inspected coordinator
execution evidence. Coordinator separately compared 72 current source/header
hashes per MCU with each build report. Normative hashes and Git index are
unchanged from baseline. No commit/push or board operations in this wave.
