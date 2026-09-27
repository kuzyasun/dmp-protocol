# MCU-02 physical execution

Owner authorized repeated flashing of both supplied bench boards on 2026-09-27.
This permission applies to these provider bench experiments; no eFuse, secure
boot, flash encryption or DTrack integration is implied.

## Hardware and deployment

Local EIM selected ESP-IDF v6.1 explicitly; esptool v5.4.0. Before deployment,
`eim run "python -m esptool --port COM23 --chip esp32s3 flash-id" v6.1` identified
ESP32-S3 QFN56 revision 0.2, 40 MHz crystal, 16 MiB flash (manufacturer c2,
device 2018), embedded 8 MiB PSRAM. COM35 with `--chip esp32c3` identified
ESP32-C3 QFN32 revision 0.4, 40 MHz crystal, 4 MiB flash (manufacturer c4,
device 6016). PSRAM is disabled in both lab configurations. Both firmware
configurations select CPU 160 MHz, UART0 115200, FreeRTOS 100 Hz, command-task
stack 12288 bytes, no RF stack.
`identification.txt` retains verbatim relevant excerpts from the coordinator's
initial flash-id tool results with command/chunk provenance; it is not a later
rerun or part of the write-flash logs. `controller.json` records Python 3.12.8
and pyserial 3.5 on the local controller.

Both images were flashed once, using the previously reviewed artifacts and
SHA-256 manifest in the parent evidence directory. From each chip's materialized
build directory, the command was:

```text
eim run "python -m esptool --chip <esp32s3|esp32c3> --port <COM23|COM35> --baud 460800 write-flash --flash-mode dio --flash-size 4MB --flash-freq 80m 0x0 bootloader/bootloader.bin 0x8000 partition_table/partition-table.bin 0x10000 dmp_provider_console.bin" v6.1
```

`flash-s3.log` and `flash-c3.log` record chip identity, exact written files and
successful verification for all three regions. Esptool reports updating the
bootloader header/digest in its outgoing image; the app build fingerprint and
artifact identities are checked separately. No erase-flash, protection changes
or secret provisioning was performed. S3 intentionally uses the same 4 MiB lab
layout even though its physical flash is larger.

## Serial runs

Run `tests/provider/console/serial_bench.py` from the repository root with
`--mode both --timeout 10` and these arguments (stdout/stderr retained separately):

| Trace | Ports | Cycles | Intended handshake pairs |
|---|---|---:|---:|
| short.jsonl | COM23 COM35 | 1 | 8 |
| repeat.jsonl | COM23 COM35 | 8 | 64 |
| reverse.jsonl | COM35 COM23 | 1 | 8 |

Each run synchronizes current command IDs. Successful runs are followed by the
next run without reset/reflash; `boot` identity must remain unchanged per chip.
Both role orientations run within every cycle. Reversing port order additionally
executes the runner's peer-1 NN setup-OOM and RNG-WRITE failure cases on C3.
Expected rejected operations must have exact result codes and no returned data.

`summarize.py` derives `results.json` from raw responses, verifies completed
summaries and identities, and reports allocator/heap/stack and command timing.
Heap numbers include the SDK and UART/task overhead. Arena peak is live charged
provider storage, not physical reservation: a full 32768-byte backing remains
reserved, plus allocator metadata, owner records and scratch. Stack high-water
is configured stack minus the smallest reported remaining bytes; this is an
observed bound for these scenarios, not a safe minimum production allocation.
Handshake timing sums each local endpoint's NEW/WRITE/READ/SPLIT command times,
excluding serial transmission and waiting for its peer. It is not end-to-end
latency or a primitive-only benchmark. Random-ephemeral results still use public
fixture static keys/PSK, not production enrollment.

## Measured results

All three runs passed: **80 handshake pairs, 3349 responses**, no timeout,
unexpected result, malformed response or reset. Per-chip boot IDs and the
reviewed source fingerprint stayed unchanged across all runs. The test exercises
each NN/XX role with fixed and hardware-generated ephemeral keys, bidirectional
traffic, out-of-order receive PN, corrupted tag and wrong AAD followed by the
authentic packet, and rejected TX nonce reuse. Expected result-code totals:
320 MAC failures, 160 invalid TX nonces, three setup OOMs, three injected entropy
failures and three invalid-state continuations. Reverse-port run places the
injected OOM/RNG cases on C3 as well as S3. This is not a full failure-ordinal
sweep on MCU.

| Observation (bytes) | ESP32-S3 | ESP32-C3 |
|---|---:|---:|
| Peak charged live provider arena, one local session | 1352 | 1408 |
| Retained arena backing | 32768 | 32768 |
| Arena metadata | 1056 | 1056 |
| Owner table / shared scratch | 192 / 2177 | 192 / 2177 |
| Observed free internal heap at responses | 346888 | 285192 |
| Minimum free heap since boot | 346872 | 285192 |
| Minimum observed largest heap block | 286720 | 147456 |
| Task stack high-water consumed out of 12288 | 2192 | 1712 |
| Final arena live bytes / blocks / wipe errors | 0 / 0 / 0 | 0 / 0 / 0 |
| Final successful allocations / releases | 788 / 788 | 774 / 774 |

The reported heap-free value was constant at every response on each MCU,
including all post-close checkpoints. No accumulation was observed over these
bounded runs; this does not prove an unbounded-duration or whole-application
absence of leaks. The smaller live provider peaks do not justify a 1.4 KiB
whole-component RAM claim or reducing the backing/stack without further tests.

Median local handshake-command time, **random ephemeral**, ten samples per
target/pattern/role, both chips configured at 160 MHz:

| Pattern / local role | ESP32-S3 | ESP32-C3 |
|---|---:|---:|
| NNpsk0 initiator | 33.249 ms | 37.305 ms |
| NNpsk0 responder | 32.778 ms | 36.951 ms |
| XX initiator | 77.157 ms | 86.189 ms |
| XX responder | 76.807 ms | 85.802 ms |

See timing scope above: these sums exclude UART and peer waiting. The three
host-observed run durations were 19.927 s, 152.713 s and 20.173 s, respectively;
the serial command/JSON exchange dominates those end-to-end scenario durations.
Raw operation distributions, trace hashes and exact values are in `results.json`.

Status: physical run accepted after independent evidence review. Recommended
next step: multiple live owners and byte-quota/admission pressure on both MCUs
using the same generic commands, before introducing a radio adapter. RF would
require a compatible entropy-source ownership change; it is not enabled here.

Independent read-only reviewer `mcu_physical_review` (GPT-6 Astra, xhigh)
recomputed the raw-trace counts, every reported timing distribution and the
resource figures; checked 100 fixed flights and 80 FINISH/READY ciphertexts
against normative vectors, 200 unchanged forwarded flights, exact failure and
cleanup sequences, command/boot/build continuity, and ten binary/config hashes.
No unresolved findings. The initial identification-log gap was closed by saving
the coordinator's original flash-id output excerpts; reviewer did not repeat
hardware operations. Coordinator acceptance is limited to this serialized UART
provider bench. P01 remains running; no radio, parallel-owner or production
memory/entropy guarantee follows. Source, normative-document and Git index
hashes remained unchanged throughout physical execution. No commit or push.
