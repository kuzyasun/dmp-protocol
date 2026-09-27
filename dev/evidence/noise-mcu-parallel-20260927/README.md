# MCU-04 concurrent independent provider owners

Status: MCU-04 accepted after independent source, build and physical evidence
review. P01 remains running.

Owner authorized the recommended parallel-operation experiment and repeated
flashing of S3 COM23 / C3 COM35. Preserve dirty work and Git index; no commit/push.
The MCU-03 image and evidence remain available for restoration.

The serial console has shared scratch/arena and is intentionally single-task.
Add a separate private probe, with a portable workload and separate pthread /
ESP-IDF ports. Each worker exclusively owns its context pair, arena and scratch;
allocation hooks route by worker identity. No cross-worker release or shared
session mutation. Initialize the backend once before workers. Serialize only
hardware entropy-source access, not entire provider operations. No RF/ADC clients.

Compare one-worker and two-worker runs. Use synchronized starts, instrument
overlapping provider-call intervals, count CPU cores observed and record each
task's stack high-water. S3 workers are pinned to distinct cores; C3 workers
share its single core (concurrency, not simultaneous CPU execution). Interval
overlap is evidence of calls in flight, not cycle-level execution simultaneity.

Each worker alternates NNpsk0/XX, checks fixed independent fixtures and fresh
random handshake pairs, directional authenticated traffic and cleanup. Use
bounded run lengths, fixed buffers and finite command/task deadlines. Report
per-worker arena, scratch and stack separately from shared SDK/port memory.
Do not infer whole-DMP production budgets or an RF transport result.

Acceptance: host pthread checks on RBO, both IDF6.1 builds, independent fixed
source review before flash, owner-authorized physical 1/2-worker comparisons,
balanced allocation cleanup and stable repeated-run memory, independent
evidence review. A timeout/failure remains a failed case, never a silent pass.

## Review and validation log

Independent source reviewer `parallel_review` (GPT-6 Astra, xhigh) found two
acceptance gaps, both fixed before physical execution: Python assertions were
replaced by explicit failures (including under `-O`), and ESP32-S3 now requires
two cores both at compilation and in HELLO/RUN validation. Regression tests
run the Python acceptance gates with optimization enabled. Review found no
remaining actionable issue in private ownership, initialization publication,
entropy locking, finite task completion, cleanup or scoped overlap accounting.
Initial core SHA-256 was `d6bcc72c8aa95d5625da6738e3233a43243104bc7e408b07920868ed9b7144b2`;
initial source hashes are in [source-hashes.json](source-hashes.json). The
scheduler repair below uses [source-fixed-hashes.json](source-fixed-hashes.json).

Initial RBO job `job_01M3H2ST8BXCW9PMHZ7805APSG` failed before building because
the submitted Bash script retained Windows CRLF. The LF-normalized retry
`job_01M3H2VF8ZJE3F1ZP0T1NBJCMF` passed 35/35 host tests, both IDF builds and
symbol checks, with no compiler warning/error lines. These preliminary binaries
are not flashed: final job `job_01M3H2YKHBQ4DT6TNVW97DD3YW` rebuilds the reviewed
acceptance fixes and additional optimized-Python regression test.

That job passed 36/36 CTests and both IDF6.1 builds. All collected hashes and 49
archive member hashes were verified. Both images were flashed and all three
written regions verified on each MCU. Source fingerprint was
`7bfe9d3cd08d650976435b9771d4bee940c319eb69053f317aacae82877b71fa`.
S3 completed all six physical cases. C3 completed four cases, then the driver
stopped on a task-watchdog diagnostic during command 5 (`RUN 2 32`). The failed
trace/stderr are retained in `physical-c3.jsonl` / `physical-c3-stderr.log`;
this attempt does not pass. Only the first watchdog diagnostic line was captured.
SDK config enables the five-second idle CPU0 watchdog without panic.

Inferred cause from the scheduler code and enabled idle watchdog: independent
one-tick worker delays can keep another worker runnable
continuously on a single core, starving IDLE despite per-worker yielding. Fix:
finite per-cycle `xEventGroupSync` rendezvous, then two-tick common idle windows,
outside instrumented provider calls. The portable checkpoint now returns an
error on timeout; a failed peer cannot leave another waiting indefinitely.
Clear arrival bits at RUN start, and report/check completed sync rounds.
Watchdog configuration is unchanged. Both MCU builds and runs must be repeated;
the pre-fix S3 pass is not substituted for verification of the modified image.

## Final build and physical verification

Fixed RBO job `job_01M3H3C1RGT7APKW87G7KWVDZP`, snapshot
`snp_01M3H3C20251JM3V0GJ99DG8M7`, content
`sha256:2c2491460f1e6847b97a9e4bbe66172b58009ff92c73ec146efd117203849f6a`
passed 36/36 host tests, both IDF6.1 builds and existing link/symbol gates.
There are no compiler warning/error lines in the build logs. The three
`provider-parallel` tests include one/two pthread workers and optimized-Python
regressions. [remote-validation-fixed.sh](remote-validation-fixed.sh) is the
exact LF-normalized submitted script. [artifacts-fixed.json](artifacts-fixed.json)
records RBO artifact hashes; every collected artifact and all 49 archive members
were verified before use. Reports/logs are in [build-fixed-results](build-fixed-results/).

The final source fingerprint reported by both boards is
`383e6818927e55aa1a4f51dc9119b77bcb10c68892512af16fe001f554ebc64f`.
App image SHA-256:

- S3: `6a32b1c159801bfb42fb39f6fe2db89239a638191e03b63081cfcfbf9ecd98b5`
- C3: `aed65b216c3e23d584cf3896cab3964b0ffa267bfcf984dba3882b9c2b6c840d`

Each board was flashed twice in this wave (initial and scheduler-fixed image).
EIM explicitly selected v6.1; esptool 5.4.0 verified all three written regions
each time. Fixed commands, from the corresponding materialized build directory:

```text
eim run "python -m esptool --chip esp32s3 --port COM23 --baud 460800 write-flash --flash-mode dio --flash-size 4MB --flash-freq 80m 0x0 bootloader/bootloader.bin 0x8000 partition_table/partition-table.bin 0x10000 dmp_provider_parallel.bin" v6.1
eim run "python -m esptool --chip esp32c3 --port COM35 --baud 460800 write-flash --flash-mode dio --flash-size 4MB --flash-freq 80m 0x0 bootloader/bootloader.bin 0x8000 partition_table/partition-table.bin 0x10000 dmp_provider_parallel.bin" v6.1
```

[flash-fixed-s3.log](flash-fixed-s3.log) and [flash-fixed-c3.log](flash-fixed-c3.log)
confirm the same MCU revisions/MACs as MCU-02, plus successful verification.
No eFuse, security protection or whole-flash erase operation was performed.
Both images use CPU 160 MHz, no PSRAM, no radio, 100 Hz ticks and the five-second
idle watchdog. Previous MCU-02 images remain in `build/mcu02-final` if the
serial-operation console is needed again.

Driver invocation from the repository root (with stdout/stderr saved alongside):

```text
python tests/provider/parallel/serial_parallel.py --port COM23 --target esp32s3 --build 383e6818927e55aa1a4f51dc9119b77bcb10c68892512af16fe001f554ebc64f --output dev/evidence/noise-mcu-parallel-20260927/physical-fixed-s3.jsonl
python tests/provider/parallel/serial_parallel.py --port COM35 --target esp32c3 --build 383e6818927e55aa1a4f51dc9119b77bcb10c68892512af16fe001f554ebc64f --output dev/evidence/noise-mcu-parallel-20260927/physical-fixed-c3.jsonl
```

Both exited 0 with empty stderr, six RUN cases each and no watchdog, timeout or
reset. New boot IDs `07c681d8` (S3) / `be1318a1` (C3) remained stable throughout
their respective sweeps. Each board completed 224 local pairs, half fixed and
half random, with both patterns and both local endpoint roles. Each pair
passed bidirectional AEAD, bad-tag rejection then original-packet acceptance.
Each board recorded 4256 allocations and 4256 releases. All per-run arenas ended
empty with zero refusal/wipe errors; no allocation occurred in instrumented
handshake read/write or packet encryption/decryption. Sync-round counts matched
every requested cycle on every active worker.

| Final observation | ESP32-S3 | ESP32-C3 |
|---|---:|---:|
| CPU cores / maximum overlapping call intervals | 2 / 2 | 1 / 2 |
| Peak live arena per worker (two local endpoints), bytes | 2704 | 2816 |
| Retained backing per worker, bytes | 8192 | 8192 |
| Metadata including endpoint records/counters per worker, bytes | 1128 | 1144 |
| Scratch per worker, bytes | 1432 | 1432 |
| Worker stack high-water used (each of two 12288-byte stacks) | 2316 | 1936 |
| Main stack high-water used out of 8192 bytes | 800 | 328 |
| Free internal heap before/after every run, bytes | 347696 | 286000 |
| Minimum free internal heap since boot, bytes | 347680 | 286000 |
| Maximum measured instrumented call interval, microseconds | 58223 | 101175 |
| SDK size report total image size, bytes | 212670 | 195088 |

The single-worker runs retain both worker stacks/backings. Per-worker peaks
must not be advertised as a one-endpoint or whole-DMP RAM budget. SDK size
reports include platform/test code and public fixtures, not just the provider.
Max call interval includes preemption, clock/measurement and entropy waits.

Eight cycles per worker took 975917 microseconds (one worker) versus 1239958
(two workers / sixteen pairs) on S3, and 1103007 versus 2036255 on C3. These are
bounded workload durations with scheduling/idle windows, not standalone crypto
throughput or radio latency. S3 recorded 111 distinct-core overlapping entries
in the short two-worker case and 447 in each longer case. C3 necessarily
recorded zero distinct-core overlaps while two calls could remain in flight.

[summarize.py](summarize.py) independently parses raw replies and checks identity,
commands, all accepted records, counters, scheduling rounds and resource bounds;
[physical-fixed-audit.json](physical-fixed-audit.json) preserves derived values
and trace hashes. The physical log contains operation summaries from the
reviewed firmware; it is not a per-primitive trace. No shared-context concurrency,
fault-ordinal sweep, unbounded soak, entropy-quality or RF claim is made.

Recommended next step: reconcile the remaining P01 gates, then run a longer
bounded soak with scheduled failures/restarts using these measured scheduling
constraints. Non-Espressif runtime and complete application resource/admission
budgets remain open. This wave does not advance P02 or integrate into DTrack.

## Final independent acceptance

Read-only reviewer `parallel_review` (GPT-6 Astra, xhigh) independently verified
the fixed source/configuration hashes, all 49 materialized artifact hashes,
host/build logs, flash verification and raw physical replies. Reported pair,
allocation, memory, timing and rendezvous counts agree with the traces. The
earlier C3 RUN 5 watchdog remains recorded as a failed attempt. No unresolved
blocking finding remains; the coordinator accepts this bounded experiment.

Compile evidence confirms custom allocator/RNG, checked startup, required
sodium fast path, serialized initialization (`NOISE_USE_PTHREAD=0`) and
`-fno-strict-aliasing`. The actual last language flag in the IDF compiler
commands is `gnu23`; the portable source/host target requests C11, so this
embedded build must not be described as a strict C11 compiler-mode check.
Final compiled core/port hashes are
`77f4790fadbb68301e4869a534285f5f1ebc50f15c6d0580187b0b026b959251` /
`0efb7de687d8d854df085aae30d44be4ccb448cdc1a8d08e0dbf16be3ae6b4ad`.

[validation.json](validation.json) records preserved baseline inputs, controller
versions, Git index identity and final trace hashes. The only post-snapshot
change to listed source inputs is a README clarification of timeout scope;
executable hashes are unchanged. Existing dirty work was preserved; no commit,
push, release or DTrack integration was performed.
