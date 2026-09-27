# MCU-05 bounded repeat-lifetime soak and planned warm resets

Status: source/host and bounded S3 physical gate accepted after independent
review. C3 first epoch accepted as partial evidence; full C3 reset scenario
did not pass. P01 running.

Frozen scope: reuse the accepted MCU-04 images and firmware source fingerprint
`383e6818927e55aa1a4f51dc9119b77bcb10c68892512af16fe001f554ebc64f`.
No firmware, provider, normative contract or build configuration changes.
Owner-authorized S3 COM23 and C3 COM35; no new flash is required.

Per MCU: three boot epochs, four `RUN 2 128` blocks per epoch: 3072 local
Noise pairs, balanced fixed/random NNpsk0/XX. The existing workload rejects a
bad tag and then accepts the original ciphertext in each direction of every
pair. These are repeated built-in packet failures, not newly configurable
fault injection or handshake-read/pin/payload failures. A pair is local to a
worker; this does not measure communication between boards.

Between completed epochs, pulse UART-bridge EN via RTS for 100ms, keeping DTR
inactive; verify a fresh boot identity and cleared command/run counters.
Reset sequencing follows the installed EIM IDF6.1 esp_pylib.serial_reset
hard_reset mapping (True asserts RTS low; reapply DTR for Windows usbser.sys).
These are two planned warm resets per MCU, not power removal/cold-boot tests.
No reset or retry follows a failed, timed-out or otherwise unknown command.
The runner retains exclusive raw JSONL files and stops on unexpected output.

Require all completion, fixed/random fixtures, arena cleanup, zero wipe errors,
allocation balance, per-cycle synchronization and worker/core overlap checks
from MCU-04. Also require stable heap across all blocks and epochs, monotonic
IDs and RUN counts, final epoch identity/counter checks and no unexpected boot
change. Firmware deadlines remain unchanged (90s completion); host bounds a
RUN at 100s and HELLO at 10s. This finite workload is not a long-term leak proof.

Host checks: RBO job `job_01M3H4GWQ3SVVEQZ7JW1AGGXE6`, snapshot
`snp_01M3H4GWYY2NEXBDRN5JQEQQYP`, content
`sha256:0cc074e9490f125f50d0b69edb167754bf6005ee952728000ecab16bbd546d44`.
Python 3.14.7 passed both ordinary and `-O` unittest discovery. Each reports
16 executions: 10 new orchestration checks plus three existing acceptance
checks discovered twice through the imported fixture class (13 unique tests).
This does not add three distinct tests. All three collected artifact hashes
were verified; [host-results](host-results/) and [artifacts.json](artifacts.json).

Commands from repository root (separate serial ports may run concurrently):

```text
python -m unittest discover -s tests/provider/parallel -p 'test_serial*.py' -v
python -O -m unittest discover -s tests/provider/parallel -p 'test_serial*.py' -v
python tests/provider/parallel/serial_soak.py --port COM23 --target esp32s3 --output dev/evidence/noise-mcu-soak-20260927/physical-s3.jsonl
python tests/provider/parallel/serial_soak.py --port COM35 --target esp32c3 --output dev/evidence/noise-mcu-soak-20260927/physical-c3.jsonl
```

Initial state/hashes are in [baseline.json](baseline.json). Preserve existing
dirty work and Git index. No commit, push, DTrack integration or RF activation.
Non-Espressif runtime, entropy quality, complete provider storage/security
coverage and whole-DMP envelopes remain separate open gates.

## Review repair and final host gate

Independent reviewer `soak_review` (GPT-6 Astra xhigh) found that startup log
filtering could ignore a watchdog/brownout or a second boot before HELLO.
The coordinator confirmed the scenario and added reset-cause/duplicate-banner
rejection. Planned resets now require exactly one ROM banner and one POWERON
reset reason before HELLO. Absence is a failure, not an inferred success.
Tests also cover C3's core/overlap gates. Removed duplicate test-class discovery.

Intermediate job `job_01M3H4NDKJECFTY3730H71RH2G` is retained in
`artifacts-fixed.json` / `host-results-fixed`. Final job
`job_01M3H4PC5N5QPNM8DKMC9R9V4P`, snapshot
`snp_01M3H4PCCV8JVXXK7WXXAQ83EH`, content
`sha256:d747d4816177a972ab5e0eddd03de791eac20cf3457f91367a6b231a76b7ec5e`
passed **18 unique tests** under ordinary and optimized Python 3.14.7.
Final artifact hashes were verified and source hashes matched the reviewed files:

- Runner: `7cb5b2da1586f7a37a3558b0308d22323007dd74366c3826d7ce166e2afeed3e`
- Tests: `2b7d9e0621c596b100b33773ec65f88bc0ee7bbfc83a69ec35d5f6e27d4f9e6d`

Source review accepted this exact snapshot before physical execution. This
wave reuses MCU-04 build/flash evidence; no new C build or flash is claimed.

## Physical results

Local Python 3.12.8 / pyserial 3.5 ran the commands above, without auto-retry.
Stdout/stderr and raw replies are retained under `physical-*`; offline
`python dev/evidence/noise-mcu-soak-20260927/audit.py` reconciles raw/accepted
records into [physical-audit.json](physical-audit.json).

| Observation | ESP32-S3 | ESP32-C3 |
|---|---:|---:|
| Completed RUN blocks / intended 12 | 12 | 4 |
| Completed local pairs | 3072 | 1024 |
| Fixed / random pairs | 1536 / 1536 | 512 / 512 |
| Allocations / frees | 58368 / 58368 | 19456 / 19456 |
| Free internal heap, constant (bytes) | 347696 | 286000 |
| Minimum free heap (bytes) | 347680 | 286000 |
| Peak charged arena per worker (bytes) | 2704 | 2816 |
| Worker stack high-water used / 12288 (bytes) | 2316 | 1936 |
| Main stack high-water used / 8192 (bytes) | 832 | 328 |
| Maximum observed provider call (us) | 58256 | 101176 |
| Sum of completed RUN durations (s) | 238.088325 | 130.564820 |
| Instrumented dual-core overlap count | 21496 | 0 |
| Planned EN pulses performed | 2 | 1 |
| Reset gates completed | 2 | 0 |

S3 passed all 18 commands/replies, with boot IDs `07c681d8`, `d6a140d6`,
`1799a908`. Each reset produced exactly one ROM banner and
`rst:0x1 (POWERON),boot:0x2b (SPI_FAST_FLASH_BOOT)`, then fresh boot identity,
zero command counter and RUN counter restarting at one. All 12 blocks reported
complete synchronization, zero live blocks/wipe errors/refusals, stable heap,
balanced fixtures, successful built-in bad-tag checks and valid core overlap.
This is bounded warm-reset and repeated-provider evidence, not cold-power or
duration-independent reliability. S3 final main-stack observation is 32 bytes
higher than MCU-04; worker stack maxima are unchanged.

C3 passed four blocks on boot `be1318a1` and the final epoch HELLO. Following
the authorized EN pulse, it answered HELLO on new boot `1e56d88b`, last_id=0,
with the expected image/IDF/target. **No ROM banner or reset-cause line was
captured**, so the runner exited 1 with `Missing planned-reset ROM evidence`.
No second-epoch RUN or second reset was attempted. The four completed blocks
are valid partial provider observations; **C3's complete MCU-05 scenario did
not pass**. Seven commands/replies exist; the failed post-reset HELLO is kept.
The evidence does not establish whether a further startup reset occurred.

Source/config review found C3 ROM logging configured `ALWAYS_ON`, default UART0
at 115200 (default TX GPIO21); no SDK setting explains the missing ROM lines.
The follow-up read-only diagnostic below establishes the ROM configuration
cause. Do not change eFuses or weaken the diagnostic gate to make this pass.

The runner's source fingerprint is the MCU-04 firmware fingerprint; it is not
a hash of this new Python script. Physical traces SHA-256:

- S3: `1bc22272fa2172a2703c17df05187b238a731b6cbb64f8672f8dc3c82a0afbea`
- C3: `1d70d2b99a56fe56eb712fb2cc866cfa003bc47dee567a0ce54d04f4e311e197`

Recommended next implementation: [remaining P01 host abort-first/ownership
checks](p01-reconciliation.md), alongside selection of a usable C3 boot-diagnostic
channel. P02 stays pending. No new MCU or RF transport is needed for
the next host checks; non-Espressif physical evidence will require a selected
board later.

## C3 read-only diagnostic and final acceptance

Coordinator ran this read-only command through EIM IDF6.1 after both runners
had exited; [c3-rom-controls.log](c3-rom-controls.log) retains the result:

```text
eim run "python -m espefuse --chip esp32c3 --port COM35 summary UART_PRINT_CONTROL DIS_USB_SERIAL_JTAG_ROM_PRINT" v6.1
```

espefuse 5.4.0 reports **UART_PRINT_CONTROL = Disable (0b11)** and
**DIS_USB_SERIAL_JTAG_ROM_PRINT = Enable (0b0)**. UART ROM output is disabled
on this board. IDF's `CONFIG_BOOT_ROM_LOG_ALWAYS_ON` leaves existing eFuses
unchanged (`components/efuse/src/esp_efuse_startup.c`); it does not undo that
setting. No eFuse write/burn, firmware write or security change was performed.
COM35 is the CH343 USB-UART bridge, not the native USB Serial/JTAG channel.
The next reset evidence needs an accessible native USB boot-log channel or
separately reviewed adequate diagnostics; do not attempt to change eFuses.

After ROM inspection an explicit EN pulse restored the current application;
[c3-post-diagnostic.jsonl](c3-post-diagnostic.jsonl) reports boot `d2500317`,
last_id=0 and the same expected firmware/target/IDF. This additional diagnostic
reset is outside MCU-05's scenario counts and is not a passed reset gate.
The ROM tool's own bootloader entry is also outside the scenario. No further
RUN was issued. S3 remains on the final completed epoch.

Independent reviewer `soak_review` checked final source hashes, both 18-test
host logs and raw physical command/reply sequences, identities, cleanup and
reset boundaries. It accepted S3's bounded physical scope and C3's first
epoch only, with no remaining source finding. The coordinator independently
reconciled raw/accepted records and measurements, and accepts those same
scopes. The full C3 scenario remains explicitly not passed. Existing dirty
work and Git index are preserved; [validation.json](validation.json) records
source/evidence integrity and permitted documentation changes.
