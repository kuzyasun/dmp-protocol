# DMP validation results

Status: stage-1 consolidation of already recorded results. This file is not an
acceptance ledger. Case status stays in `dev/DMP_Normative_Cases.json`. Raw
traces removed from the worktree remain in commit
`fc83b84354d16bd72164d37eb5b5e9efd862f321` (`git show <commit>:<path>`).

Inspected revision: `feat/initial-version` at
`fc83b84354d16bd72164d37eb5b5e9efd862f321` (P11 reassembly commit, 2026-10-04).
The correction plan's evidence census was the parent
`fdf0456e0a0c79118c77061f7fdf1ad5136a879c`. Host, provider, and physical
results below are separate. None of them is SEC-1 endpoint acceptance, a
production RAM budget, or a DTrack/physical-transport claim.

`PROFILE_HASH` remains SHA-256 of the original complete manifest bytes. This
cleanup did not change manifests, wire format, or admission code.

## P09–P11 host endpoint

Configuration at `profiles/deployments/direct-nnpsk0.json`, contract
`DMP-test-manifest/2`: `message_bytes` 1024, `peers` 1,
`assemblies_per_peer` 1, `assembly_tombstones_per_peer` 16. Resource charges
used by admission: sender 4, result 4, assembly 1, assembly tombstone 16,
history 8, correlation 4. Tombstone design charge is 16 × 48 = 768 bytes.
Assembly design charge is 1536 bytes per slot (1024-byte message plus the
512-byte metadata/slot reserve enforced by the validators).

P10 reliability still requires separate caller payload/metadata storage for
that profile, in bytes:

```text
sender + result + receive: (4 + 4 + 1) * 1024 = 9216
history + correlation metadata: (8 + 4) * 255 = 3060
subtotal = 12276
```

`255` is `DMP_MAX_HEADER_BYTES`. This subtotal excludes slot structs, adapter
frames, identity state, reassembly payload, tombstones, security, stream
state, and stack. Profile admission still asks for
`DMP_PROFILE_ADMIT_SCRATCH_BYTES` = 419936, of which 419424 is the JSON key
region in `src/identity/profile_admit.c`. That scratch is not a message buffer.

| Package | Recorded result | Limits |
|---|---|---|
| P09 | Targeted host CTest 4/4 (`profiles.contract`, `identity.context`, `identity.profile_admit`, `identity.profile_parity`). Python profiles 23/23. `python tools/check_core_allocators.py build/host/libdmp.a --nm nm`: no allocator references. | Host/profile only. SEC-1 rerun still required later. Evidence: `dev/evidence/p09-identity-20261003/README.md`. |
| P10 | `reliability.direct` passed on the GCC/MinGW tree `build/p10-host-gcc`. Full host CTest 14/15. GCC 15.2.0, CMake/CTest 3.28.1, Python 3.12.8. | `harness.subprocess` failed with Windows `PermissionError` on `%TEMP%` Python temp directories. Unrelated to reliability. Not MCU or SEC-1. |
| P11 | `cmake --build build/host --parallel 2` then `ctest --test-dir build/host --output-on-failure`: 17/17, including `reassembly.direct`, `identity.profile_parity`, `profiles.contract`, `harness.subprocess`. Python profiles 24/24. Six deployment manifests accepted. | Package status is `review`, not `done`. Final review of snapshot `snap-7d33a9cebada7cf17a2683b3` did not start (`INPUT_UNSUPPORTED` on `__pycache__` bytecode). No handshake, AEAD, or replay check. Evidence: `dev/evidence/p11-reassembly-20261003/README.md`. |

P03's frozen per-endpoint reserve statement (77440 direct / 81280 radio bytes)
predates the tombstone charge. Current manifests add 768 tombstone bytes.
That historical README was kept as the P03 record, not updated.

## Provider and MCU measurements

Toolchain notes below are copied from the experiment READMEs. Provider tests
do not qualify the composed DMP endpoint.

| ID | Revision / config | Decisive measurement | Outcome |
|---|---|---|---|
| PN-01 | Fork `44722c19f7795dd409b46728712067fac87ffc53`. Host GCC 15.2.0. | 7/7 CTest. 32 JSON packets decrypt at descending PN. | Host receive-nonce seam accepted. Inherited vectors: 52 run, 988 skipped. |
| DH-01 | Fork `c707782972b9c9015a8a1ba06724a07572306d50`. | X25519 all-zero shared secret rejected before MixKey. | Host sodium scope accepted. Entropy, erasure, and MCU runtime open. |
| RNG-01 | Checked `noise_rand_bytes_checked`. | 10/10 CTest after the post-init failure path. | Host accepted. MCU entropy quality not measured. `.su.txt` files are compile-only stack reports, not a stack budget. |
| INIT-01 / BINIT-01 | Checked backend startup. | Final BINIT suite 31/31 CTest. Failed entropy returns; canary bytes cleared. | Serialized host startup accepted. Cold-boot entropy quality open. Original backend still aborts on OS entropy failure. |
| MEM-01 | Host allocation tracker. | NNpsk0 peak live requested heap 2650 bytes; XX 3322 bytes. Setup requested 14/2394 and 18/3066 bytes. | Owned-heap cleanup accepted. Excludes allocator metadata, stack, and MCU. |
| MEM-02 | Layout summary retained at `dev/evidence/noise-arena-20260927/layout-summary.json`. | `NoiseHandshakeState`: host 240 bytes align 8; Cortex-M4 and ESP32-S3 176 bytes align 4. Arena metadata: host 2112 bytes; MCU layouts 1056 bytes. | Host storage/quota accepted. Not a whole-endpoint budget. |
| MEM-03 | Serialized multi-owner host arena. | Test reserves 32768 backing + 2112 metadata bytes. `four_parallel` was deferred. | Host live-owner quota accepted. Physical stack/heap came later. |
| MCU-01 | ESP-IDF v6.0.2, Xtensa GCC 15.2.0, 4 MB flash, no PSRAM, `-Os`. Cortex-M4 archive only (Arm GNU 13.3.1). | Noise flash code/data 9164+522; checked libsodium 16370+12800 code/data and 143 static DIRAM bytes. Image size 128172 baseline vs 200348 provider test (+72176). | Compile/link only. No MCU execution. |
| MCU-02 | S3 COM23 / C3 COM35. Stack 12288 bytes. No RF. pyserial 3.5, Python 3.12.8. | 80 handshake pairs, 3349 responses. Free heap constant: S3 346888, C3 285192 bytes. Min free heap 346872 / 285192. Stack high-water 2192 / 1712 of 12288. Images 206160 / 187984 bytes. | Physical provider bench accepted. Not ESP-NOW/Bluetooth and not DMP transport. |
| MCU-03 | Same boards and MCU-02 image fingerprint `71e3a2d6…`. Quotas 2048, 3840, 4096, 8192, 32768 bytes. | 10 cases, 383.147 s, 5717 responses, 36 completed candidates. Peak charged arena 7280 / 7568 bytes. At 3840, C3 Split OOM at 3824 live bytes. Heap/stack minima continue the MCU-02 boot. | Serialized pressure accepted. Not concurrent tasks or a production envelope. |
| MCU-04 | ESP-IDF 6.1, CPU 160 MHz, no PSRAM, no radio, 100 Hz tick, 5 s idle watchdog. Final fingerprint `383e6818…`. | Fixed image: 36/36 host CTest; each board 224 local pairs; allocations 4256 = releases. Peak arena/worker 2704 / 2816 bytes. Worker stack 2316 / 1936 of 12288. Main stack 800 / 328 of 8192. Free heap 347696 / 286000. Image 212670 / 195088 bytes. | Passed after the C3 watchdog fix. Pre-fix C3 `RUN 2 32` did not pass. C3 overlap is two calls in flight on one core. |
| MCU-05 | Same fingerprint as MCU-04. Plan: 3 epochs × 4 × `RUN 2 128` = 3072 pairs per MCU. | S3 completed 3072 pairs and 2 warm resets (boot IDs `07c681d8`, `d6a140d6`, `1799a908`). C3 completed 1024 pairs, then failed closed: missing ROM banner after EN (`Missing planned-reset ROM evidence`). | S3 scoped soak accepted. Full C3 scenario not passed. Cause recorded as UART ROM disabled by existing eFuse. No eFuse change. |
| P08 | CI commit `2bccf6bf7f8fac3e84eeeadfb8f570cdee5b0bb4`, Actions run 37118205823. ESP-IDF v6.0.2. | Linux GCC 13/13, Windows MSVC 12/12, Clang fuzz 14/14 with 1000-execution smokes. ESP32-S3 image 153033 bytes; linked `libdmp.a` contribution 7330 bytes; no core allocator references. Cortex-M4 `libdmp.a` per-object size totals in `dev/evidence/fuzz-p08-20261003/cortex-m4-libdmp-size.txt` (base 544, codec 4978, crc32c 190, cobs 732, stream 1987, including comment/attributes). | Compile/link and host tests. The checkpoint README that says P08 is open is older than this CI acceptance. Downloaded map files were CI artifacts, not tree files. |

`BOUNDARY-01` has no passed check.

## Failed or deferred

- P11 final independent review of the post-reserve snapshot.
- P01 umbrella: entropy quality, full resource sensitivity, non-Espressif
  runtime, and the C3 MCU-05 reset scenario.
- MCU-04 pre-fix C3 watchdog run.
- P10 `harness.subprocess` on this Windows host.
- Embedded JSON admission and the 419936-byte scratch (unchanged in this stage).
- P12 and every SEC-1/physical DMP transport gate.
- `four_parallel` was never counted as a passed serialized test.

## Replay

Host checks that do not flash hardware:

```text
python -m unittest tests.profiles.test_deployments.DeploymentTests.test_resource_input_hashes_match_source_bytes
cmake --build build/host --parallel 2
ctest --test-dir build/host --output-on-failure
```

The resource-input test was rerun after this cleanup: 1 test, OK.
`profiles/deployments/resource-inputs.json` still hashes these paths, with
CRLF normalized to LF. That normalization is not `PROFILE_HASH`:

- `dev/evidence/noise-arena-20260927/README.md`
- `dev/evidence/noise-arena-20260927/layout-summary.json`
- `dev/evidence/noise-owners-20260927/README.md`
- `dev/evidence/noise-mcu-20260927/README.md`
- `dev/evidence/noise-mcu-console-20260927/physical/README.md`
- `tests/provider/experiment_manifest.json`
- `dev/evidence/implementation-transition-20260927/README.md`

Physical provider commands are historical and need a fresh owner flash
authorization. They are not part of this cleanup:

```text
python tests/provider/console/serial_pressure.py --ports COM23 COM35 --output dev/evidence/noise-mcu-pressure-20260927/physical.jsonl --timeout 10
python tests/provider/parallel/serial_parallel.py --port COM23 --target esp32s3 --build 383e6818927e55aa1a4f51dc9119b77bcb10c68892512af16fe001f554ebc64f --output dev/evidence/noise-mcu-parallel-20260927/physical-fixed-s3.jsonl
python tests/provider/parallel/serial_parallel.py --port COM35 --target esp32c3 --build 383e6818927e55aa1a4f51dc9119b77bcb10c68892512af16fe001f554ebc64f --output dev/evidence/noise-mcu-parallel-20260927/physical-fixed-c3.jsonl
python tests/provider/parallel/serial_soak.py --port COM23 --target esp32s3 --output dev/evidence/noise-mcu-soak-20260927/physical-s3.jsonl
python tests/provider/parallel/serial_soak.py --port COM35 --target esp32c3 --output dev/evidence/noise-mcu-soak-20260927/physical-c3.jsonl
```

Removed traces are recovered from
`fc83b84354d16bd72164d37eb5b5e9efd862f321`, not from the worktree.

## Worktree cleanup

Confirming commit for every removed path:
`fc83b84354d16bd72164d37eb5b5e9efd862f321`.
330 tracked files, 44666522 worktree bytes. Sorted path-list SHA-256
`d34cc7fc0ac08494b3518656a7c26625b668d65b2cd33bdcc92fceedc8cf0c08`
(UTF-8, LF between paths, trailing LF). Classes: `*.jsonl`, `*.log`, `*.gz`,
`*report.json`, `*nm-defined.txt`, `*nm-undefined.txt`, `*-size.txt` outside
`fuzz-p08`, `*summary.json` except `layout-summary.json`, plus
`noise-mcu-20260927/esp32s3-size-archives.json` and `backend-files.json`.

Measurement, worktree file lengths:

```text
git ls-files -- dev/evidence | ForEach-Object { (Get-Item -LiteralPath $_).Length }
Get-ChildItem -Recurse -File dev/evidence | Measure-Object Length -Sum
```

| Set | Before | After |
|---|---:|---:|
| Tracked `dev/evidence` present in the worktree | 551 files, 45565518 bytes | 221 files, 898996 bytes |
| `dev/evidence` on disk, including ignored files | 553 files, 45991275 bytes | 223 files, 1324753 bytes |

The on-disk remainder exceeds 1 MiB by the two ignored, uncommitted
`dev/evidence/p00/initial-*.patch` files (425757 bytes). They were not deleted.
Tracked retained evidence is 898996 bytes.

## Stage 3 buffer budget

Host ABI from the existing `build/host` tree (GCC 15.2.0). Measured
`sizeof(dmp_reassembly_tombstone)` is 48, so the manifest charge stays
16 × 48 = 768 bytes. The struct was not padded.

Other measured state objects, not folded into the eight-array budget:
`dmp_identity_slot` 64, `dmp_reliability` 544, `dmp_reassembly_slot` 176,
`dmp_reassembly` 336, `dmp_reassembly_tombstone` 48. The reliability and
reassembly objects grew when the admitted profile gained the eight R3 fields
and the reassembly slot gained the collection timer, status counter, and
expected-status snapshot. Crypto is excluded. Stack is excluded. JSON admission
scratch is 0. These sizes are not total endpoint RAM.

The eight-array sum is sender, result, and receive payload, history and
correlation metadata (`DMP_MAX_HEADER_BYTES` 255), adapter frames, and, when
reassembly is claimed, assembly payload plus assembly metadata. It is not
total endpoint RAM.

Corrected `direct-nnpsk0.json` limits: `message_bytes` 1024, `fragments` 16,
`chunk_bytes` 64, `encoded_mtu` 263, `peers` 1, `control_slots` 2,
`adapter_slots` 3, `assemblies_per_peer` 1, `assembly_tombstones_per_peer` 16.
Endpoint charges used by the 16384-byte row: sender 4, result 4, history 8,
correlation 4, assembly 1, assembly tombstone 16, adapter 3. That pair admits,
and `dmp_reliability_init` accepts it. The reliability reserve formula was not
changed. A handwritten profile mutated to `adapter_slots == control_slots == 2`
is still rejected by `dmp_reliability_init`; `dmp_config_admit` now rejects
that pair as well.

Each supported row below was admitted with `dmp_config_admit` and initialized
with `dmp_reliability_init`. Where one reliability frame can hold
`message_bytes` (`message_bytes + 48 <= encoded_mtu`), the row completes a
request/result exchange of that full size (`dmp_reliability_submit_req`, poll,
`dmp_reliability_on_rx`, `dmp_reliability_complete`, and the returning
`dmp_reliability_on_rx`). Rows that claim reassembly also call
`dmp_reassembly_init` and complete every slice of the stated chunk until
`message_bytes` is delivered; the slice count equals `fragments`. Unfragmented
rows omit both assembly byte lengths and do not charge reassembly tombstones.
None of these rows is total endpoint RAM. Crypto and stack stay excluded.

The 16384-byte row is the direct profile. `encoded_mtu` 263 cannot hold a
1024-byte reliability frame, so its 64-byte request/result call is only a
frame that fits and is not an exchange of `message_bytes`. The admitted
message is delivered by reassembly: 1024 bytes, chunk 64, 16 slices.
The smaller rows deliver their own stated message size. They are smaller
capabilities, not labeled as direct-nnpsk0.

Command, existing `build/host`, after `cmake --build build/host`:

```text
ctest --test-dir build/host --output-on-failure -R "identity.profile_admit"
```

`identity.profile_admit` passed and printed the rows. State bytes 608 are one
`dmp_identity_slot` (64) plus one `dmp_reliability` (544). State bytes 1120
add one `dmp_reassembly_slot` (176) and one `dmp_reassembly` (336). The
eight-array sums are unchanged: the new fields are state, not payload buffers.

| Budget (bytes) | Result | Capability | message_bytes | fragments | chunk_bytes | encoded_mtu | Slots | Eight-array sum (bytes) | State bytes | Tombstone bytes | Crypto | Stack | JSON scratch | What ran |
|---:|---|---|---:|---:|---:|---:|---|---:|---:|---:|---|---|---:|---|
| 1024 | supported | Unfragmented reliability; omits assembly payload and metadata; no reassembly tombstones | 64 | 1 | 32 | 112 | peers 1, sender 1, result 1, history 1, correlation 1, adapter 2, control 1, assembly 0, tombstone slots 0 | 926 | 608 | 0 | excluded | excluded | 0 | admit, reliability init, 64-byte request/result exchange |
| 2048 | supported | Same shape, message 256 | 256 | 1 | 128 | 304 | peers 1, sender 1, result 1, history 1, correlation 1, adapter 2, control 1, assembly 0, tombstone slots 0 | 1886 | 608 | 0 | excluded | excluded | 0 | admit, reliability init, 256-byte request/result exchange |
| 3072 | supported | Same shape, message 384 | 384 | 1 | 128 | 432 | peers 1, sender 1, result 1, history 1, correlation 1, adapter 2, control 1, assembly 0, tombstone slots 0 | 2526 | 608 | 0 | excluded | excluded | 0 | admit, reliability init, 384-byte request/result exchange |
| 4096 | supported | Full 256-byte reliability exchange plus reassembly of the same 256 bytes as two 128-byte slices; one tombstone, not the direct 16 | 256 | 2 | 128 | 304 | peers 1, sender 1, result 1, history 1, correlation 1, adapter 2, control 1, assembly 1, tombstone slots 1 | 2397 | 1120 | 48 | excluded | excluded | 0 | admit, reliability init, 256-byte request/result exchange, reassembly init, 256-byte two-slice reassembly |
| 8192 | supported | Unfragmented 1024-byte message; not direct-nnpsk0 (MTU 1072, fragments 1, one slot of each kind) | 1024 | 1 | 512 | 1072 | peers 1, sender 1, result 1, history 1, correlation 1, adapter 2, control 1, assembly 0, tombstone slots 0 | 5726 | 608 | 0 | excluded | excluded | 0 | admit, reliability init, 1024-byte request/result exchange |
| 16384 | supported | direct-nnpsk0 limits, adapter 3 and control 2; 64-byte reliability frame fits MTU 263 and is not the message exchange; reassembly delivers 1024 bytes as 16 slices of 64 | 1024 | 16 | 64 | 263 | peers 1, sender 4, result 4, history 8, correlation 4, adapter 3, control 2, assembly 1, tombstone slots 16 | 14344 | 1120 | 768 | excluded | excluded | 0 | admit, reliability init, 64-byte fitting frame, reassembly init, 1024-byte 16-slice reassembly |

Unfragmented sums omit assembly payload and assembly metadata:
`3*message_bytes + 255 + 255 + 2*encoded_mtu`.
The 4096-byte sum is `3*256 + 255 + 255 + 2*304 + 256 + 255`.
The 14344-byte sum is `4*1024 + 4*1024 + 1024 + 8*255 + 4*255 + 3*263 + 1*1024 + 1*255`.
Tombstone bytes 768 are 16 × 48. Tombstone bytes 48 are 1 × 48.

## P15 host provider retained and scratch

Compared with `profiles/deployments/direct-nnpsk0.json`, role `endpoint`,
target `portable-host.endpoint.v1`. That row charges `provider_retained`
count 3 × 12288 = 36864 bytes and `provider_scratch` count 1 × 4096 = 4096
bytes. There is no separate retained/scratch row for the composed endpoint
object beyond those provider charges.

The integrated host session in `endpoint.protected_context` and
`endpoint.protected_drain` puts both peers on one provider. Measured Noise
block accounting, not stack and not the 419936-byte JSON scratch:

| Run | Peak retained (bytes) | Live retained (bytes) | Blocks | Largest single allocation (bytes) |
|---|---:|---:|---:|---:|
| One active association | 2826 | 816 | 6 | 256 |
| Active plus draining attempts | 3338 | 1328 | 10 | 256 |

Both high-water totals sit inside one endpoint's 36864-byte retained charge.
The largest allocation sits inside the 4096-byte scratch charge. This is host
provider accounting, not an MCU budget. The 2^24 frame ceiling was not moved.
