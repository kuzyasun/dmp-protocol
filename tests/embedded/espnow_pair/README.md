# ESP-NOW S3/C3 radio smoke tests

This isolated ESP-IDF test project builds for ESP32-S3 and ESP32-C3. It has a
pair runner for one S3 and one C3, and a four-board runner that configures one
S3 radio context with three unicast C3 peers. Both images run the same
`src/core/codec.c` parser/encoder. Each C3 checks the source station MAC and
frame structure, then echoes the received bytes unchanged. The S3 checks the
echo bytes and sequence against its submitted frame. Its bounded peer table
holds up to three C3 MACs.

This is an unauthenticated radio and Core codec smoke test. It does not run
SEC-1, `dmp_endpoint`, SAMPLE-1, or prove application acceptance. The ESP-NOW
send callback is a MAC-layer result; the separate S3 echo comparison proves
that the test payload returned. Do not describe this image as an authenticated
DMP endpoint or production radio binding.

Both harnesses report these separate bounds:

| Quantity | Bytes | Meaning in this smoke |
| --- | ---: | --- |
| Decoded Core MTU | 256 | DMP DIRECT-1 Core frame reference limit |
| Stream R encoded MTU | 263 | DMP DIRECT-1 encoded stream-frame reference limit; this smoke uses packet framing |
| ESP-NOW v1 payload maximum | 250 | Maximum complete Core packet carried by ESP-NOW v1 |

This run keeps each test packet at or below 250 bytes. It does not establish
delivery for the full 256-byte Core or 263-byte Stream R limits.
The runner assigns a fresh 64-bit session token for every invocation. Both
images confirm it before peer setup, and each Core payload begins with that
token so delayed packets from a prior run are rejected. This reserves the first
8 DMP payload bytes and sets the minimum payload size to 8 bytes.

## Build

Run from the repository root with ESP-IDF 6.1 selected by EIM. The two targets
must use different build directories.

```powershell
eim run "idf.py -C tests/embedded/espnow_pair -B build/espnow-pair-esp32s3 -DIDF_TARGET=esp32s3 build"
eim run "idf.py -C tests/embedded/espnow_pair -B build/espnow-pair-esp32c3 -DIDF_TARGET=esp32c3 build"
```

The image selects the native USB Serial/JTAG console, a fixed 2.4 GHz channel
1, and unencrypted unicast ESP-NOW peers. It requires no NVS provisioning or
board GPIO configuration. Both target builds use the same 4 MiB custom
partition table: NVS (24 KiB), PHY init (4 KiB), one factory app (3,008 KiB),
and a 1 MiB flash coredump partition at `0x300000`. The ESP-IDF coredump
configuration admits up to 64 tasks; the 1 MiB reservation gives the test
image room for task control blocks and stacks, and the intentional panic check
must still confirm that the target runtime dump fits. S3 PSRAM task stacks are
disabled. This is a test-image layout, not a DMP product partition contract.

## Prepare the pair

Before writing an image, identify each target and read its flash size. The
build selects a 4 MiB layout. Stop if the chip does not match its selected
image or its flash is smaller than 4 MiB. For the current bench mapping, S3 is
COM37 and the first C3 is COM36. COM38 and COM39 remain available for the later
multi-board run. Recheck the chip identity if USB port assignments change.

The owner authorized a one-time full-flash erase of the four bench boards for
this test setup. Before erasing, verify each port's detected target and flash
size with `esptool --port <PORT> chip-id` and `esptool --port <PORT> flash-id`.
Proceed only if COM37 is the S3, COM36/COM38/COM39 are C3s, and every flash is
at least 4 MiB. A full erase removes all flash contents, including NVS and any
existing firmware; it does not alter eFuses.

After identity verification, erase each board:

```powershell
esptool --chip esp32s3 --port COM37 erase-flash
esptool --chip esp32c3 --port COM36 erase-flash
esptool --chip esp32c3 --port COM38 erase-flash
esptool --chip esp32c3 --port COM39 erase-flash
```

Then flash the matching target image:

```powershell
eim run "idf.py -C tests/embedded/espnow_pair -B build/espnow-pair-esp32s3 -p COM37 flash"
eim run "idf.py -C tests/embedded/espnow_pair -B build/espnow-pair-esp32c3 -p COM36 flash"
eim run "idf.py -C tests/embedded/espnow_pair -B build/espnow-pair-esp32c3 -p COM38 flash"
eim run "idf.py -C tests/embedded/espnow_pair -B build/espnow-pair-esp32c3 -p COM39 flash"
```

The Python runner leaves DTR and RTS inactive so opening the USB ports does not
request a reset. The `serial_coredump.py` hardware-only utility sends
`CORE_DUMP_TEST`, records raw serial bytes through the panic and reboot, reads
the coredump partition without writing flash, verifies it is not entirely
erased, and extracts its length-prefixed ELF image as `core.elf`. Decode that
file with the matching target ELF from the ESP-IDF build:

```powershell
python tests/embedded/espnow_pair/serial_coredump.py --port COM37 --target esp32s3
esp-coredump --chip esp32s3 info_corefile --core-format elf `
  --core <evidence-directory>\core.elf `
  build\espnow-pair-esp32s3\dmp_espnow_pair.elf
```

Use `--chip esp32c3`, the C3 port, C3 core file, and C3 ELF for a C3 dump. If
the target GDB executable is not on `PATH`, pass it with `--gdb`. This
intentional crash is only a coredump smoke check; it is not part of the
ESP-NOW exchange runner.
The utility is not registered in CTest and must only be run against an attached
physical board. Its CI-safe event-validation unit tests do not open serial or
claim that a flash coredump was produced.

## Capture and test

Install `pyserial` in the selected Python environment if it is not present.
Run the bounded default pair scenario from the repository root:

```powershell
python tests/embedded/espnow_pair/serial_pair.py --s3-port COM37 --c3-port COM36 --count 10 --payload-bytes 64
```

The runner requests fresh INFO records, programs each board with the other's
station MAC, enables C3 echo, and submits one S3 run. It never retries a serial
command. A passing result requires one successful S3 MAC send callback, one
valid C3 receive, one successful C3 echo send callback, and one byte-identical
S3 echo for every sequence, in order. The default run writes a unique directory
under `dev/evidence/espnow-pair/` containing:

- exact per-port raw byte streams (`*.raw.bin`);
- timestamped line indexes, preserving each line's base64 bytes (`*.timeline.jsonl`);
- exact host command bytes and write results (`commands.jsonl`);
- image SHA-256 values, port inventory, parameters, and the computed verdict (`run.json`).

The CI-safe mock suite lives separately under `tests/host/espnow_pair/` and is
registered as `host.espnow_pair.serial_stub` in root CTest. It drives the same
runner against an in-memory serial pair and deterministic ESP-NOW echo stub;
it does not open a COM port or exercise the ESP-IDF radio driver. Run it locally
with `python -m unittest discover -s tests/host/espnow_pair -p 'test_*.py' -v`.
The physical serial runner in this directory is deliberately not registered in
CTest and is not run by CI.

## One S3 with three C3 peers

All four ports must be free; close Serial Monitor before starting the runner.
The script opens the ports with DTR and RTS inactive and writes the same fresh
session token to each image. The three C3 MACs are read from their live `INFO`
records; they are never hard-coded.

```powershell
python tests/embedded/espnow_pair/serial_four.py `
  --s3-port COM37 --c3-ports COM36,COM38,COM39 `
  --count-per-peer 10 --payload-bytes 64
```

The S3 adds all three C3 peers to one radio context. It then sends 30 probes
one at a time, round-robin, and verifies a matching echo from the selected
peer for each probe. The default evidence records ten successful exchanges per
C3, all four MACs, callbacks, exact serial input/output bytes and per-board
counters. This is still unauthenticated radio/Core-codec evidence. The send
queue is serialized; this does not exercise SEC-1, `dmp_endpoint`, SAMPLE-1,
four authenticated peers, or `four_parallel`. Three separate pair runs are
also not a substitute for a production one-endpoint multi-peer test.
